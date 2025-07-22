import numpy as np
from typing import List, Dict, Tuple, Optional
import hashlib
from sentence_transformers import SentenceTransformer
import faiss
import pickle
import json
from pathlib import Path

class CodeVectorStore:
    """
    向量存储系统，用于代码语义搜索和相似漏洞检测
    """
    
    def __init__(self, model_name: str = "microsoft/codebert-base"):
        """
        初始化向量存储
        Args:
            model_name: 用于代码嵌入的模型
        """
        self.model = SentenceTransformer(model_name)
        self.index = None
        self.code_snippets = []
        self.metadata = []
        self.dimension = None
        
    def _compute_embedding(self, text: str) -> np.ndarray:
        """
        计算文本的向量嵌入
        """
        return self.model.encode([text])[0]
    
    def add_code_snippets(self, snippets: List[Dict[str, any]]):
        """
        添加代码片段到向量存储
        Args:
            snippets: 包含 'code', 'file_path', 'function_name', 'language' 等字段的字典列表
        """
        embeddings = []
        
        for snippet in snippets:
            # 创建用于嵌入的文本表示
            text_representation = self._create_text_representation(snippet)
            embedding = self._compute_embedding(text_representation)
            embeddings.append(embedding)
            
            # 存储原始代码和元数据
            self.code_snippets.append(snippet['code'])
            self.metadata.append({
                'file_path': snippet.get('file_path', ''),
                'function_name': snippet.get('function_name', ''),
                'language': snippet.get('language', ''),
                'line_start': snippet.get('line_start', 0),
                'hash': hashlib.md5(snippet['code'].encode()).hexdigest()
            })
        
        # 初始化或更新 FAISS 索引
        embeddings_array = np.array(embeddings).astype('float32')
        
        if self.index is None:
            self.dimension = embeddings_array.shape[1]
            self.index = faiss.IndexFlatL2(self.dimension)
        
        self.index.add(embeddings_array)
    
    def _create_text_representation(self, snippet: Dict[str, any]) -> str:
        """
        创建代码片段的文本表示，用于嵌入
        """
        parts = []
        
        if snippet.get('function_name'):
            parts.append(f"Function: {snippet['function_name']}")
        
        if snippet.get('language'):
            parts.append(f"Language: {snippet['language']}")
        
        # 添加代码内容
        parts.append(snippet['code'])
        
        return "\n".join(parts)
    
    def search_similar_code(self, query_code: str, k: int = 5) -> List[Tuple[str, Dict, float]]:
        """
        搜索相似的代码片段
        Args:
            query_code: 查询代码
            k: 返回的结果数量
        Returns:
            列表，每个元素为 (代码片段, 元数据, 相似度分数)
        """
        if self.index is None or self.index.ntotal == 0:
            return []
        
        # 计算查询的嵌入
        query_embedding = self._compute_embedding(query_code)
        query_embedding = np.array([query_embedding]).astype('float32')
        
        # 搜索最相似的向量
        distances, indices = self.index.search(query_embedding, min(k, self.index.ntotal))
        
        results = []
        for i, (idx, distance) in enumerate(zip(indices[0], distances[0])):
            if idx < len(self.code_snippets):
                similarity_score = 1 / (1 + distance)  # 转换距离为相似度分数
                results.append((
                    self.code_snippets[idx],
                    self.metadata[idx],
                    similarity_score
                ))
        
        return results
    
    def find_vulnerability_patterns(self, vulnerability_code: str, k: int = 10) -> List[Dict]:
        """
        基于已知漏洞代码查找相似的潜在漏洞
        """
        similar_codes = self.search_similar_code(vulnerability_code, k)
        
        potential_vulnerabilities = []
        for code, metadata, similarity in similar_codes:
            if similarity > 0.7:  # 相似度阈值
                potential_vulnerabilities.append({
                    'code': code,
                    'metadata': metadata,
                    'similarity': similarity,
                    'risk_score': similarity * 0.8  # 基于相似度的风险评分
                })
        
        return potential_vulnerabilities
    
    def save(self, path: str):
        """
        保存向量存储到磁盘
        """
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # 保存 FAISS 索引
        if self.index is not None:
            faiss.write_index(self.index, str(path / "index.faiss"))
        
        # 保存元数据和代码片段
        with open(path / "metadata.json", 'w') as f:
            json.dump({
                'code_snippets': self.code_snippets,
                'metadata': self.metadata,
                'dimension': self.dimension
            }, f)
    
    def load(self, path: str):
        """
        从磁盘加载向量存储
        """
        path = Path(path)
        
        # 加载 FAISS 索引
        index_path = path / "index.faiss"
        if index_path.exists():
            self.index = faiss.read_index(str(index_path))
        
        # 加载元数据和代码片段
        with open(path / "metadata.json", 'r') as f:
            data = json.load(f)
            self.code_snippets = data['code_snippets']
            self.metadata = data['metadata']
            self.dimension = data['dimension']
    
    def build_vulnerability_database(self, known_vulnerabilities: List[Dict]):
        """
        构建已知漏洞的向量数据库
        Args:
            known_vulnerabilities: 包含 'code', 'type', 'severity' 等字段的漏洞列表
        """
        vuln_snippets = []
        
        for vuln in known_vulnerabilities:
            snippet = {
                'code': vuln['code'],
                'function_name': f"VULN_{vuln['type']}",
                'language': vuln.get('language', 'unknown'),
                'file_path': f"vulnerability_db/{vuln['type']}"
            }
            vuln_snippets.append(snippet)
        
        self.add_code_snippets(vuln_snippets)
