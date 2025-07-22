import os
import ast
import re
from typing import List, Dict, Tuple, Optional
from pathlib import Path
import subprocess

class CodeLoader:
    """
    加载和预处理代码文件，支持多种语言的基础解析
    """
    
    SUPPORTED_EXTENSIONS = {
        '.py': 'python',
        '.js': 'javascript', 
        '.ts': 'typescript',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.go': 'go',
        '.php': 'php',
        '.rb': 'ruby'
    }
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists():
            raise ValueError(f"Repository path {repo_path} does not exist")
    
    def load_files(self, extensions: Optional[List[str]] = None) -> Dict[str, str]:
        """
        加载指定扩展名的所有代码文件
        """
        if extensions is None:
            extensions = list(self.SUPPORTED_EXTENSIONS.keys())
        
        files = {}
        for ext in extensions:
            for file_path in self.repo_path.rglob(f"*{ext}"):
                # 跳过常见的非源代码目录
                if any(part in file_path.parts for part in ['.git', '__pycache__', 'node_modules', '.env', 'venv']):
                    continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        relative_path = str(file_path.relative_to(self.repo_path))
                        files[relative_path] = f.read()
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
        
        return files
    
    def extract_functions(self, code: str, language: str) -> List[Dict[str, any]]:
        """
        提取代码中的函数定义
        """
        if language == 'python':
            return self._extract_python_functions(code)
        elif language in ['javascript', 'typescript']:
            return self._extract_js_functions(code)
        else:
            # 其他语言使用通用正则
            return self._extract_generic_functions(code, language)
    
    def _extract_python_functions(self, code: str) -> List[Dict[str, any]]:
        """
        使用 AST 提取 Python 函数
        """
        functions = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append({
                        'name': node.name,
                        'line_start': node.lineno,
                        'args': [arg.arg for arg in node.args.args],
                        'body': ast.get_source_segment(code, node),
                        'type': 'function'
                    })
                elif isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            functions.append({
                                'name': f"{node.name}.{item.name}",
                                'line_start': item.lineno,
                                'args': [arg.arg for arg in item.args.args],
                                'body': ast.get_source_segment(code, item),
                                'type': 'method',
                                'class': node.name
                            })
        except SyntaxError:
            pass
        return functions
    
    def _extract_js_functions(self, code: str) -> List[Dict[str, any]]:
        """
        使用正则提取 JavaScript/TypeScript 函数
        """
        functions = []
        # 匹配函数声明
        func_pattern = re.compile(
            r'(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)|'
            r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|'
            r'(\w+)\s*:\s*(?:async\s*)?\([^)]*\)\s*(?:=>|{)'
        )
        
        for match in func_pattern.finditer(code):
            line_num = code[:match.start()].count('\n') + 1
            if match.group(1):  # function declaration
                name = match.group(1)
                args = match.group(2)
            elif match.group(3):  # arrow function
                name = match.group(3)
                args = ""
            elif match.group(4):  # method
                name = match.group(4)
                args = ""
            
            functions.append({
                'name': name,
                'line_start': line_num,
                'args': [arg.strip() for arg in args.split(',') if arg.strip()],
                'type': 'function'
            })
        
        return functions
    
    def _extract_generic_functions(self, code: str, language: str) -> List[Dict[str, any]]:
        """
        通用函数提取（基于正则）
        """
        functions = []
        patterns = {
            'java': r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)',
            'cpp': r'(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*(?:const)?\s*{',
            'c': r'(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*{',
            'go': r'func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\([^)]*\)',
            'php': r'(?:public|private|protected)?\s*(?:static)?\s*function\s+(\w+)\s*\([^)]*\)',
            'ruby': r'def\s+(\w+)(?:\([^)]*\))?'
        }
        
        pattern = patterns.get(language)
        if pattern:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                functions.append({
                    'name': match.group(1),
                    'line_start': line_num,
                    'type': 'function'
                })
        
        return functions
    
    def find_imports(self, code: str, language: str) -> List[str]:
        """
        查找代码中的导入语句
        """
        imports = []
        
        if language == 'python':
            import_pattern = re.compile(r'^\s*(?:from\s+(\S+)\s+)?import\s+(.+)', re.MULTILINE)
            for match in import_pattern.finditer(code):
                if match.group(1):
                    imports.append(f"from {match.group(1)} import {match.group(2)}")
                else:
                    imports.append(f"import {match.group(2)}")
        
        elif language in ['javascript', 'typescript']:
            import_pattern = re.compile(r'^\s*import\s+.+\s+from\s+[\'"](.+)[\'"]', re.MULTILINE)
            require_pattern = re.compile(r'require\s*\(\s*[\'"](.+)[\'"]\s*\)', re.MULTILINE)
            
            imports.extend([match.group(0) for match in import_pattern.finditer(code)])
            imports.extend([match.group(0) for match in require_pattern.finditer(code)])
        
        elif language == 'java':
            import_pattern = re.compile(r'^\s*import\s+(.+);', re.MULTILINE)
            imports = [match.group(0) for match in import_pattern.finditer(code)]
        
        return imports
    
    def get_code_metrics(self, code: str) -> Dict[str, int]:
        """
        获取代码的基本度量信息
        """
        lines = code.split('\n')
        return {
            'total_lines': len(lines),
            'code_lines': len([l for l in lines if l.strip() and not l.strip().startswith('#')]),
            'comment_lines': len([l for l in lines if l.strip().startswith('#')]),
            'blank_lines': len([l for l in lines if not l.strip()])
        }
