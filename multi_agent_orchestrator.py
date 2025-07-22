"""
Multi-Agent Security Analysis Orchestrator
协调多个专门的安全分析代理
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import asyncio
from concurrent.futures import ThreadPoolExecutor

from langchain_google_vertexai import VertexAI
from langchain.agents import initialize_agent, Tool
from langchain.agents.agent_types import AgentType
from langchain.memory import ConversationSummaryBufferMemory
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

from tools.vulnerability_analyzer_agent import VulnerabilityAnalyzerAgent, VulnerabilityFinding
from tools.code_loader import CodeLoader
from tools.vector_store import CodeVectorStore

@dataclass
class SecurityReport:
    """综合安全报告"""
    vulnerabilities: List[VulnerabilityFinding]
    code_quality_issues: List[Dict]
    dependency_risks: List[Dict]
    architecture_concerns: List[Dict]
    overall_risk_score: float
    summary: str
    recommendations: List[str]

class SecurityAgents:
    """专门的安全分析代理集合"""
    
    def __init__(self, model_name: str = "gemini-2.5-pro"):
        # 代码理解代理
        self.code_understanding_agent = self._create_code_understanding_agent(model_name)
        
        # 架构分析代理
        self.architecture_agent = self._create_architecture_agent(model_name)
        
        # 依赖分析代理
        self.dependency_agent = self._create_dependency_agent(model_name)
        
        # 业务逻辑分析代理
        self.business_logic_agent = self._create_business_logic_agent(model_name)
        
        # 漏洞分析代理（使用专门的类）
        self.vulnerability_agent = VulnerabilityAnalyzerAgent(model_name)
    
    def _create_code_understanding_agent(self, model_name: str):
        """创建代码理解代理"""
        llm = VertexAI(model_name=model_name, temperature=0.2)
        
        prompt = PromptTemplate(
            input_variables=["code", "question"],
            template="""You are a senior software engineer analyzing code.

Code:
```
{code}
```

Question: {question}

Provide a detailed technical analysis focusing on:
1. Code structure and design patterns
2. Data flow and control flow
3. External dependencies and integrations
4. Potential performance issues
5. Code maintainability concerns

Be specific and technical in your analysis."""
        )
        
        return LLMChain(llm=llm, prompt=prompt)
    
    def _create_architecture_agent(self, model_name: str):
        """创建架构安全分析代理"""
        llm = VertexAI(model_name=model_name, temperature=0.2)
        
        prompt = PromptTemplate(
            input_variables=["code_structure"],
            template="""You are a security architect analyzing application architecture.

Application Structure:
{code_structure}

Analyze the architecture for security concerns:
1. Trust boundaries and data flow
2. Authentication and authorization architecture
3. Service communication security
4. Data storage and encryption
5. API security design
6. Microservice security (if applicable)
7. Defense in depth implementation

Provide findings as JSON:
[
  {{
    "concern": "Missing API Gateway",
    "severity": "HIGH",
    "description": "Direct service exposure without central security controls",
    "recommendation": "Implement API Gateway for centralized security"
  }}
]"""
        )
        
        return LLMChain(llm=llm, prompt=prompt)
    
    def _create_dependency_agent(self, model_name: str):
        """创建依赖安全分析代理"""
        llm = VertexAI(model_name=model_name, temperature=0.2)
        
        prompt = PromptTemplate(
            input_variables=["dependencies", "language"],
            template="""You are a security expert analyzing software dependencies.

Language: {language}
Dependencies:
{dependencies}

Analyze for:
1. Known vulnerable dependencies (even if versions aren't specified)
2. Outdated packages that may have security issues
3. Suspicious or potentially malicious packages
4. Supply chain risks
5. License compliance issues

Provide findings as JSON:
[
  {{
    "package": "package-name",
    "issue": "Known vulnerability CVE-XXXX-XXXX",
    "severity": "CRITICAL",
    "description": "Remote code execution vulnerability",
    "recommendation": "Upgrade to version X.X.X or later"
  }}
]"""
        )
        
        return LLMChain(llm=llm, prompt=prompt)
    
    def _create_business_logic_agent(self, model_name: str):
        """创建业务逻辑安全分析代理"""
        llm = VertexAI(model_name=model_name, temperature=0.2)
        
        prompt = PromptTemplate(
            input_variables=["code", "context"],
            template="""You are a security expert analyzing business logic vulnerabilities.

Code:
```
{code}
```

Context: {context}

Analyze for business logic flaws:
1. Race conditions in critical operations
2. Time-of-check to time-of-use (TOCTOU) issues
3. Insufficient workflow enforcement
4. Price/quantity manipulation
5. Privilege escalation through business logic
6. Missing rate limiting on sensitive operations
7. Improper state management

Focus on logic flaws that traditional security scanners might miss.

Provide findings as JSON array with vulnerability details."""
        )
        
        return LLMChain(llm=llm, prompt=prompt)

class MultiAgentOrchestrator:
    """
    多代理协调器 - 协调多个专门的安全分析代理
    """
    
    def __init__(self, model_name: str = "gemini-2.5-pro"):
        self.agents = SecurityAgents(model_name)
        self.coordinator_llm = VertexAI(
            model_name=model_name,
            temperature=0.1,
            max_output_tokens=8192
        )
        
        # 协调器提示
        self.coordinator_prompt = PromptTemplate(
            input_variables=["task", "code_context"],
            template="""You are the chief security officer coordinating a security analysis.

Task: {task}
Code Context: {code_context}

Based on this task, determine:
1. Which security agents should be involved
2. What specific questions each agent should investigate
3. How to prioritize the analysis
4. What additional context each agent needs

Provide a coordination plan as JSON:
{{
  "agents_needed": ["vulnerability", "architecture", "dependencies", "business_logic", "code_understanding"],
  "analysis_priority": ["vulnerability", "dependencies", "architecture"],
  "specific_focuses": {{
    "vulnerability": "Focus on injection attacks and authentication",
    "architecture": "Examine service boundaries and data flow",
    "dependencies": "Check for known CVEs and supply chain risks"
  }},
  "coordination_notes": "Start with vulnerability scan, then correlate with architecture"
}}"""
        )
        
        self.synthesis_prompt = PromptTemplate(
            input_variables=["findings"],
            template="""Synthesize the security findings from multiple agents into a comprehensive report.

Findings:
{findings}

Create a unified security assessment that:
1. Combines and correlates findings from all agents
2. Eliminates duplicates while preserving unique insights
3. Prioritizes issues by real-world exploitability
4. Provides an overall risk score (0-10)
5. Gives actionable recommendations

Format as a comprehensive security report."""
        )
        
        self.executor = ThreadPoolExecutor(max_workers=5)
    
    async def analyze_code(self, code: str, language: str = "python", 
                          context: str = "") -> SecurityReport:
        """
        使用多个代理分析代码
        """
        # 步骤 1: 协调器决定分析策略
        coordination_plan = await self._get_coordination_plan(code, context)
        
        # 步骤 2: 并行执行各代理分析
        analysis_tasks = []
        
        if "vulnerability" in coordination_plan.get("agents_needed", []):
            analysis_tasks.append(
                self._run_vulnerability_analysis(code, language, context)
            )
        
        if "architecture" in coordination_plan.get("agents_needed", []):
            analysis_tasks.append(
                self._run_architecture_analysis(code, language)
            )
        
        if "dependencies" in coordination_plan.get("agents_needed", []):
            analysis_tasks.append(
                self._run_dependency_analysis(code, language)
            )
        
        if "business_logic" in coordination_plan.get("agents_needed", []):
            analysis_tasks.append(
                self._run_business_logic_analysis(code, context)
            )
        
        # 并行执行所有分析
        results = await asyncio.gather(*analysis_tasks)
        
        # 步骤 3: 综合所有发现
        report = await self._synthesize_findings(results, coordination_plan)
        
        return report
    
    async def _get_coordination_plan(self, code: str, context: str) -> Dict:
        """获取协调计划"""
        chain = LLMChain(llm=self.coordinator_llm, prompt=self.coordinator_prompt)
        
        # 创建简化的代码上下文
        code_lines = code.split('\n')
        code_context = f"Code has {len(code_lines)} lines, language detected from patterns"
        
        try:
            result = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                chain.run,
                {"task": "Comprehensive security analysis", "code_context": code_context}
            )
            
            import json
            return json.loads(result)
        except Exception as e:
            # 默认计划
            return {
                "agents_needed": ["vulnerability", "dependencies"],
                "analysis_priority": ["vulnerability"],
                "specific_focuses": {}
            }
    
    async def _run_vulnerability_analysis(self, code: str, language: str, context: str) -> Dict:
        """运行漏洞分析"""
        findings = await asyncio.get_event_loop().run_in_executor(
            self.executor,
            self.agents.vulnerability_agent.analyze_code,
            code, language, context
        )
        
        return {
            "agent": "vulnerability",
            "findings": findings
        }
    
    async def _run_architecture_analysis(self, code: str, language: str) -> Dict:
        """运行架构分析"""
        # 简化的架构信息提取
        structure_info = f"Language: {language}\nCode structure analysis based on patterns"
        
        result = await asyncio.get_event_loop().run_in_executor(
            self.executor,
            self.agents.architecture_agent.run,
            {"code_structure": structure_info}
        )
        
        try:
            import json
            findings = json.loads(result)
        except:
            findings = []
        
        return {
            "agent": "architecture",
            "findings": findings
        }
    
    async def _run_dependency_analysis(self, code: str, language: str) -> Dict:
        """运行依赖分析"""
        # 提取导入/依赖
        dependencies = self._extract_dependencies(code, language)
        
        result = await asyncio.get_event_loop().run_in_executor(
            self.executor,
            self.agents.dependency_agent.run,
            {"dependencies": dependencies, "language": language}
        )
        
        try:
            import json
            findings = json.loads(result)
        except:
            findings = []
        
        return {
            "agent": "dependencies",
            "findings": findings
        }
    
    async def _run_business_logic_analysis(self, code: str, context: str) -> Dict:
        """运行业务逻辑分析"""
        result = await asyncio.get_event_loop().run_in_executor(
            self.executor,
            self.agents.business_logic_agent.run,
            {"code": code, "context": context}
        )
        
        try:
            import json
            findings = json.loads(result)
        except:
            findings = []
        
        return {
            "agent": "business_logic",
            "findings": findings
        }
    
    def _extract_dependencies(self, code: str, language: str) -> str:
        """提取代码中的依赖"""
        dependencies = []
        
        if language == "python":
            import re
            # 查找 import 语句
            imports = re.findall(r'^\s*(?:from\s+(\S+)|import\s+(\S+))', code, re.MULTILINE)
            for imp in imports:
                dep = imp[0] if imp[0] else imp[1]
                if dep and not dep.startswith('.'):
                    dependencies.append(dep.split('.')[0])
        
        elif language == "javascript":
            import re
            # 查找 require 和 import
            requires = re.findall(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]', code)
            imports = re.findall(r'import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]', code)
            dependencies.extend(requires)
            dependencies.extend(imports)
        
        return '\n'.join(set(dependencies))
    
    async def _synthesize_findings(self, results: List[Dict], 
                                 coordination_plan: Dict) -> SecurityReport:
        """综合所有发现生成报告"""
        # 整理所有发现
        all_vulnerabilities = []
        architecture_concerns = []
        dependency_risks = []
        business_logic_issues = []
        
        for result in results:
            agent = result.get("agent")
            findings = result.get("findings", [])
            
            if agent == "vulnerability" and isinstance(findings, list):
                all_vulnerabilities.extend(findings)
            elif agent == "architecture":
                architecture_concerns = findings if isinstance(findings, list) else []
            elif agent == "dependencies":
                dependency_risks = findings if isinstance(findings, list) else []
            elif agent == "business_logic":
                business_logic_issues = findings if isinstance(findings, list) else []
        
        # 计算风险分数
        risk_score = self._calculate_risk_score(
            all_vulnerabilities, 
            architecture_concerns,
            dependency_risks
        )
        
        # 生成摘要和建议
        chain = LLMChain(llm=self.coordinator_llm, prompt=self.synthesis_prompt)
        
        findings_text = f"""
Vulnerabilities: {len(all_vulnerabilities)} found
- Critical: {sum(1 for v in all_vulnerabilities if hasattr(v, 'severity') and v.severity == 'CRITICAL')}
- High: {sum(1 for v in all_vulnerabilities if hasattr(v, 'severity') and v.severity == 'HIGH')}

Architecture Concerns: {len(architecture_concerns)}
Dependency Risks: {len(dependency_risks)}
Business Logic Issues: {len(business_logic_issues)}
"""
        
        synthesis = await asyncio.get_event_loop().run_in_executor(
            self.executor,
            chain.run,
            {"findings": findings_text}
        )
        
        # 提取建议
        recommendations = self._extract_recommendations(
            all_vulnerabilities,
            architecture_concerns,
            dependency_risks
        )
        
        return SecurityReport(
            vulnerabilities=all_vulnerabilities,
            code_quality_issues=[],  # 可以扩展
            dependency_risks=dependency_risks,
            architecture_concerns=architecture_concerns,
            overall_risk_score=risk_score,
            summary=synthesis,
            recommendations=recommendations
        )
    
    def _calculate_risk_score(self, vulnerabilities: List, 
                            architecture_concerns: List,
                            dependency_risks: List) -> float:
        """计算总体风险分数"""
        score = 0.0
        
        # 基于漏洞严重性
        for vuln in vulnerabilities:
            if hasattr(vuln, 'severity'):
                if vuln.severity == 'CRITICAL':
                    score += 2.5
                elif vuln.severity == 'HIGH':
                    score += 1.5
                elif vuln.severity == 'MEDIUM':
                    score += 0.8
                elif vuln.severity == 'LOW':
                    score += 0.3
        
        # 架构问题
        score += len(architecture_concerns) * 0.5
        
        # 依赖风险
        score += len(dependency_risks) * 0.4
        
        # 归一化到 0-10
        return min(10.0, score)
    
    def _extract_recommendations(self, vulnerabilities: List,
                               architecture_concerns: List,
                               dependency_risks: List) -> List[str]:
        """提取优先建议"""
        recommendations = []
        
        # 从漏洞中提取
        critical_vulns = [v for v in vulnerabilities 
                         if hasattr(v, 'severity') and v.severity == 'CRITICAL']
        
        if critical_vulns:
            recommendations.append("🚨 URGENT: Fix critical vulnerabilities immediately")
            for vuln in critical_vulns[:3]:  # 前3个关键漏洞
                if hasattr(vuln, 'recommendation'):
                    recommendations.append(f"• {vuln.recommendation}")
        
        # 架构建议
        if architecture_concerns:
            recommendations.append("🏗️ Architecture improvements needed")
        
        # 依赖建议
        if dependency_risks:
            recommendations.append("📦 Update vulnerable dependencies")
        
        return recommendations 