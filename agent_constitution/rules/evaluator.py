"""AST-based safe expression evaluator for policy conditions."""

import ast
import operator
from typing import Any, Dict, Tuple, Union


# Whitelist of allowed AST node types for safe evaluation
ALLOWED_NODES = {
    # Literals
    ast.Constant,
    ast.Str,  # For Python < 3.8 compatibility
    ast.Num,  # For Python < 3.8 compatibility
    ast.List,
    ast.Tuple,
    ast.Dict,
    ast.Set,
    
    # Expressions
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.BoolOp,
    ast.Compare,
    ast.Call,
    ast.IfExp,
    
    # Operators
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
    ast.Pow,
    ast.FloorDiv,
    ast.USub,
    ast.UAdd,
    ast.Not,
    ast.Invert,
    ast.And,
    ast.Or,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.Is,
    ast.IsNot,
    ast.In,
    ast.NotIn,
    
    # Names and attributes
    ast.Name,
    ast.Load,
    ast.Attribute,
    ast.Subscript,
    ast.Index,  # For Python < 3.9 compatibility
    
    # Comprehensions (limited)
    ast.ListComp,
    ast.SetComp,
    ast.GeneratorExp,
    ast.comprehension,
    
    # Other
    ast.Slice,
    ast.ExtSlice,
}

# Whitelist of allowed built-in functions
ALLOWED_BUILTINS = {
    'len', 'range', 'enumerate', 'zip', 'map', 'filter',
    'abs', 'all', 'any', 'bool', 'dict', 'float', 'int',
    'list', 'max', 'min', 'round', 'set', 'str', 'sum',
    'tuple', 'type', 'sorted', 'reversed', 'isinstance',
    'hasattr', 'getattr', 'setattr', 'dir', 'help',
}

# Safe operators mapping
OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.FloorDiv: operator.floordiv,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
    ast.Not: operator.not_,
    ast.Invert: operator.invert,
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
    ast.In: lambda x, y: x in y,
    ast.NotIn: lambda x, y: x not in y,
    ast.And: lambda *args: all(args),
    ast.Or: lambda *args: any(args),
}


class EvaluatorError(Exception):
    """Raised when expression evaluation fails."""
    pass


class UnsafeExpressionError(EvaluatorError):
    """Raised when expression contains unsafe operations."""
    pass


class ExpressionValidator(ast.NodeVisitor):
    """Validates AST nodes against allowed whitelist."""
    
    def __init__(self):
        self.errors = []
    
    def generic_visit(self, node):
        if type(node) not in ALLOWED_NODES:
            self.errors.append(f"Disallowed node type: {type(node).__name__}")
        return super().generic_visit(node)
    
    def visit_Call(self, node):
        # Check for dangerous calls
        if isinstance(node.func, ast.Name):
            if node.func.id in {'eval', 'exec', 'compile', '__import__', 'open', 'input'}:
                self.errors.append(f"Dangerous function call: {node.func.id}")
        self.generic_visit(node)
    
    def visit_Name(self, node):
        # Check for dangerous names
        if isinstance(node.ctx, ast.Store):
            if node.id in {'__import__', '__builtins__', '__globals__', '__locals__'}:
                self.errors.append(f"Dangerous name: {node.id}")
        self.generic_visit(node)


def validate_expression(expression: str) -> Tuple[bool, str]:
    """Validate that an expression is safe to evaluate.
    
    Args:
        expression: The expression string to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    
    validator = ExpressionValidator()
    validator.visit(tree)
    
    if validator.errors:
        return False, "; ".join(validator.errors)
    
    return True, ""


class SafeEvaluator(ast.NodeVisitor):
    """Safely evaluates AST expressions with limited context."""
    
    def __init__(self, context: Dict[str, Any]):
        self.context = context
        self.builtins = {name: __builtins__[name] for name in ALLOWED_BUILTINS 
                        if name in __builtins__}
    
    def visit(self, node):
        if type(node) not in ALLOWED_NODES:
            raise UnsafeExpressionError(f"Disallowed node type: {type(node).__name__}")
        return super().visit(node)
    
    def visit_Expression(self, node):
        return self.visit(node.body)
    
    def visit_Constant(self, node):
        return node.value
    
    # For Python < 3.8 compatibility
    def visit_Str(self, node):
        return node.s
    
    def visit_Num(self, node):
        return node.n
    
    def visit_List(self, node):
        return [self.visit(elt) for elt in node.elts]
    
    def visit_Tuple(self, node):
        return tuple(self.visit(elt) for elt in node.elts)
    
    def visit_Dict(self, node):
        return {self.visit(k): self.visit(v) for k, v in zip(node.keys, node.values)}
    
    def visit_Set(self, node):
        return {self.visit(elt) for elt in node.elts}
    
    def visit_Name(self, node):
        if node.id in self.context:
            return self.context[node.id]
        if node.id in self.builtins:
            return self.builtins[node.id]
        raise NameError(f"Name '{node.id}' is not defined")
    
    def visit_BinOp(self, node):
        left = self.visit(node.left)
        right = self.visit(node.right)
        op_type = type(node.op)
        if op_type not in OPERATORS:
            raise UnsafeExpressionError(f"Unsupported binary operator: {op_type.__name__}")
        return OPERATORS[op_type](left, right)
    
    def visit_UnaryOp(self, node):
        operand = self.visit(node.operand)
        op_type = type(node.op)
        if op_type not in OPERATORS:
            raise UnsafeExpressionError(f"Unsupported unary operator: {op_type.__name__}")
        return OPERATORS[op_type](operand)
    
    def visit_BoolOp(self, node):
        values = [self.visit(v) for v in node.values]
        op_type = type(node.op)
        if op_type == ast.And:
            return all(values)
        elif op_type == ast.Or:
            return any(values)
        raise UnsafeExpressionError(f"Unsupported boolean operator: {op_type.__name__}")
    
    def visit_Compare(self, node):
        left = self.visit(node.left)
        for op, comparator in zip(node.ops, node.comparators):
            right = self.visit(comparator)
            op_type = type(op)
            if op_type not in OPERATORS:
                raise UnsafeExpressionError(f"Unsupported comparison: {op_type.__name__}")
            if not OPERATORS[op_type](left, right):
                return False
            left = right
        return True
    
    def visit_Call(self, node):
        # Get function
        if isinstance(node.func, ast.Name):
            if node.func.id not in ALLOWED_BUILTINS and node.func.id not in self.context:
                raise UnsafeExpressionError(f"Function '{node.func.id}' is not allowed")
            func = self.builtins.get(node.func.id) or self.context.get(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            obj = self.visit(node.func.value)
            func = getattr(obj, node.func.attr)
        else:
            func = self.visit(node.func)
        
        # Evaluate arguments
        args = [self.visit(arg) for arg in node.args]
        kwargs = {kw.arg: self.visit(kw.value) for kw in node.keywords}
        
        return func(*args, **kwargs)
    
    def visit_IfExp(self, node):
        test = self.visit(node.test)
        if test:
            return self.visit(node.body)
        else:
            return self.visit(node.orelse)
    
    def visit_Attribute(self, node):
        obj = self.visit(node.value)
        return getattr(obj, node.attr)
    
    def visit_Subscript(self, node):
        obj = self.visit(node.value)
        if isinstance(node.slice, ast.Constant):
            key = node.slice.value
        elif isinstance(node.slice, ast.Index):  # Python < 3.9
            key = self.visit(node.slice.value)
        else:
            key = self.visit(node.slice)
        return obj[key]
    
    def visit_Slice(self, node):
        lower = self.visit(node.lower) if node.lower else None
        upper = self.visit(node.upper) if node.upper else None
        step = self.visit(node.step) if node.step else None
        return slice(lower, upper, step)
    
    def visit_ListComp(self, node):
        return self._visit_comprehension(node, list)
    
    def visit_SetComp(self, node):
        return self._visit_comprehension(node, set)
    
    def visit_GeneratorExp(self, node):
        return self._visit_comprehension(node, list)
    
    def _visit_comprehension(self, node, result_type):
        """Handle list/set comprehensions."""
        # This is a simplified implementation
        # Full comprehension support would require more complex handling
        raise UnsafeExpressionError("Comprehensions are not fully supported yet")


def evaluate_expression(expression: str, context: Dict[str, Any] = None) -> Any:
    """Safely evaluate an expression with the given context.
    
    Args:
        expression: The expression string to evaluate
        context: Dictionary of variables available in the expression
        
    Returns:
        The result of the expression evaluation
        
    Raises:
        EvaluatorError: If the expression is invalid or unsafe
    """
    if context is None:
        context = {}
    
    # Validate first
    is_valid, error = validate_expression(expression)
    if not is_valid:
        raise EvaluatorError(f"Invalid expression: {error}")
    
    # Parse and evaluate
    try:
        tree = ast.parse(expression, mode='eval')
        evaluator = SafeEvaluator(context)
        return evaluator.visit(tree)
    except Exception as e:
        raise EvaluatorError(f"Evaluation error: {e}")


# Convenience functions for common operations
def evaluate_comparison(left: Any, operator_str: str, right: Any) -> bool:
    """Evaluate a simple comparison."""
    ops = {
        '==': operator.eq,
        '!=': operator.ne,
        '<': operator.lt,
        '<=': operator.le,
        '>': operator.gt,
        '>=': operator.ge,
        'in': lambda a, b: a in b,
        'not in': lambda a, b: a not in b,
    }
    if operator_str not in ops:
        raise ValueError(f"Unknown operator: {operator_str}")
    return ops[operator_str](left, right)


def evaluate_logical(expressions: list, operator_str: str = 'and') -> bool:
    """Evaluate logical combinations."""
    if operator_str == 'and':
        return all(expressions)
    elif operator_str == 'or':
        return any(expressions)
    else:
        raise ValueError(f"Unknown logical operator: {operator_str}")