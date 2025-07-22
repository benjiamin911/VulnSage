### Vertex AI + LangChain 项目模板：漏洞分析 Agent

# 第一步：导入所需库
from langchain_google_vertexai import VertexAI
from langchain.agents import initialize_agent, Tool
from langchain.agents.agent_types import AgentType
from langchain.memory import ConversationBufferMemory
from langchain.callbacks import StreamingStdOutCallbackHandler
import json
import sys
import asyncio
from pathlib import Path

# 导入自定义工具模块
from tools.code_loader import CodeLoader
from tools.vulnerability_analyzer_agent import VulnerabilityAnalyzerAgent
from tools.vector_store import CodeVectorStore
from multi_agent_orchestrator import MultiAgentOrchestrator

# 第二步：配置主协调 AI 模型
llm = VertexAI(
    model_name="gemini-2.5-pro",
    temperature=0.2,
    max_output_tokens=20480,
    streaming=True,  # 启用流式输出
    callbacks=[StreamingStdOutCallbackHandler()]
)

# 第三步：初始化组件
multi_agent_orchestrator = MultiAgentOrchestrator()
vulnerability_analyzer = VulnerabilityAnalyzerAgent()
code_loader = None  # 将在需要时初始化
vector_store = CodeVectorStore()

# 第四步：定义高级工具

def analyze_code_with_ai(code: str) -> str:
    """
    使用 AI 代理分析代码片段的安全漏洞
    """
    # 尝试检测语言
    language = "python"  # 默认
    if "function" in code and "{" in code:
        language = "javascript"
    elif "public class" in code or "private void" in code:
        language = "java"
    elif "<?php" in code:
        language = "php"
    
    # 使用 LLM 驱动的漏洞分析器
    findings = vulnerability_analyzer.analyze_code(code, language)
    
    if not findings:
        return "✅ AI Analysis: No vulnerabilities detected in this code snippet."
    
    # 格式化报告
    report = "🔍 AI Security Analysis Report\n"
    report += "="*60 + "\n"
    report += f"Found {len(findings)} potential vulnerabilities:\n\n"
    
    for i, finding in enumerate(findings, 1):
        report += f"{i}. {finding.vulnerability_type} ({finding.severity})\n"
        report += f"   📍 Location: {finding.location}\n"
        report += f"   📝 Description: {finding.description}\n"
        report += f"   💥 Impact: {finding.impact}\n"
        report += f"   ✅ Recommendation: {finding.recommendation}\n"
        report += f"   🧠 AI Reasoning: {finding.reasoning}\n"
        report += f"   🎯 Confidence: {finding.confidence:.0%}\n\n"
    
    return report

async def analyze_code_multi_agent(code: str) -> str:
    """
    使用多代理系统进行深度安全分析
    """
    # 检测语言
    language = "python"
    if "function" in code and "{" in code:
        language = "javascript"
    elif "public class" in code or "private void" in code:
        language = "java"
    
    # 执行多代理分析
    report = await multi_agent_orchestrator.analyze_code(code, language)
    
    # 格式化综合报告
    output = "🛡️ Multi-Agent Security Analysis Report\n"
    output += "="*70 + "\n"
    output += f"Overall Risk Score: {report.overall_risk_score:.1f}/10\n\n"
    
    output += "📊 Summary:\n"
    output += report.summary + "\n\n"
    
    if report.vulnerabilities:
        output += f"🔍 Vulnerabilities Found: {len(report.vulnerabilities)}\n"
        for vuln in report.vulnerabilities[:5]:  # 显示前5个
            output += f"  • {vuln.vulnerability_type} - {vuln.severity}\n"
    
    if report.recommendations:
        output += "\n💡 Top Recommendations:\n"
        for rec in report.recommendations:
            output += f"  {rec}\n"
    
    return output

def multi_agent_analysis_sync(code: str) -> str:
    """
    同步包装器，用于在 LangChain 工具中使用异步函数
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(analyze_code_multi_agent(code))
    finally:
        loop.close()

def suggest_fix_for_vulnerability(vulnerable_code: str) -> str:
    """
    为易受攻击的代码建议安全修复
    """
    # 首先分析代码找出漏洞
    findings = vulnerability_analyzer.analyze_code(vulnerable_code)
    
    if not findings:
        return "No vulnerabilities found to fix."
    
    # 为第一个发现的漏洞生成修复建议
    vuln = findings[0]
    
    fix_suggestion = vulnerability_analyzer.suggest_secure_alternative(
        vulnerable_code, 
        vuln.vulnerability_type
    )
    
    return fix_suggestion

def analyze_repository(repo_path: str) -> str:
    """
    分析整个代码仓库的安全漏洞
    """
    global code_loader
    
    try:
        code_loader = CodeLoader(repo_path)
        files = code_loader.load_files()
        
        if not files:
            return "❌ No supported code files found in the repository."
        
        all_findings = []
        analyzed_files = 0
        
        for file_path, code in files.items():
            # 限制分析文件数量以避免超时
            if analyzed_files >= 10:
                break
                
            # 确定语言
            ext = Path(file_path).suffix
            language = code_loader.SUPPORTED_EXTENSIONS.get(ext, 'unknown')
            
            if language != 'unknown' and len(code.strip()) > 0:
                findings = vulnerability_analyzer.analyze_code(
                    code, 
                    language,
                    f"File: {file_path}"
                )
                
                for finding in findings:
                    finding.location = f"{file_path}:{finding.location}"
                    all_findings.append(finding)
                
                analyzed_files += 1
        
        if not all_findings:
            return f"✅ Analyzed {analyzed_files} files. No vulnerabilities detected!"
        
        # 按严重性排序
        all_findings.sort(key=lambda x: 
                         ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x.severity))
        
        report = f"🔍 Repository Security Analysis Complete\n"
        report += f"Analyzed {analyzed_files} files (limited to 10 for performance)\n"
        report += f"Found {len(all_findings)} potential vulnerabilities\n\n"
        
        # 统计
        severity_counts = {}
        for finding in all_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                report += f"{severity}: {severity_counts[severity]} issues\n"
        
        report += "\n" + "="*60 + "\n\n"
        
        # 显示前10个最严重的问题
        report += "Top Security Issues:\n\n"
        for i, finding in enumerate(all_findings[:10], 1):
            report += f"{i}. {finding.vulnerability_type} ({finding.severity})\n"
            report += f"   📍 {finding.location}\n"
            report += f"   📝 {finding.description}\n\n"
        
        if len(all_findings) > 10:
            report += f"... and {len(all_findings) - 10} more issues\n"
        
        return report
    
    except Exception as e:
        return f"❌ Error analyzing repository: {str(e)}"

def compare_code_security(code1: str, code2: str) -> str:
    """
    比较两段代码的安全性
    """
    # 分析两段代码
    findings1 = vulnerability_analyzer.analyze_code(code1, "python", "First code snippet")
    findings2 = vulnerability_analyzer.analyze_code(code2, "python", "Second code snippet")
    
    report = "🔄 Security Comparison Report\n"
    report += "="*50 + "\n\n"
    
    report += f"Code 1: {len(findings1)} vulnerabilities found\n"
    report += f"Code 2: {len(findings2)} vulnerabilities found\n\n"
    
    if len(findings1) == 0 and len(findings2) == 0:
        report += "✅ Both code snippets appear to be secure!\n"
    elif len(findings1) < len(findings2):
        report += "✅ Code 1 is more secure (fewer vulnerabilities)\n"
    elif len(findings1) > len(findings2):
        report += "✅ Code 2 is more secure (fewer vulnerabilities)\n"
    else:
        report += "⚠️  Both have the same number of vulnerabilities\n"
    
    # 详细比较
    if findings1:
        report += "\n📋 Code 1 vulnerabilities:\n"
        for f in findings1:
            report += f"  • {f.vulnerability_type} ({f.severity})\n"
    
    if findings2:
        report += "\n📋 Code 2 vulnerabilities:\n"
        for f in findings2:
            report += f"  • {f.vulnerability_type} ({f.severity})\n"
    
    return report

# 第五步：包装为 LangChain Tool
tools = [
    Tool(
        name="AnalyzeCodeWithAI",
        func=analyze_code_with_ai,
        description="使用 AI 深度分析代码片段的安全漏洞。输入代码字符串，返回 AI 推理的详细漏洞报告。"
    ),
    Tool(
        name="MultiAgentAnalysis",
        func=multi_agent_analysis_sync,
        description="使用多个专门的 AI 代理进行全面的安全分析，包括漏洞、架构、依赖等多个维度。"
    ),
    Tool(
        name="SuggestSecureFix",
        func=suggest_fix_for_vulnerability,
        description="为包含漏洞的代码提供安全的修复建议和最佳实践。"
    ),
    Tool(
        name="AnalyzeRepository",
        func=analyze_repository,
        description="使用 AI 分析整个代码仓库的安全漏洞。输入仓库路径。"
    ),
    Tool(
        name="CompareCodeSecurity",
        func=compare_code_security,
        description="比较两段代码的安全性，帮助选择更安全的实现。"
    )
]

# 第六步：初始化 Agent with Memory
memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)

agent = initialize_agent(
    tools=tools,
    llm=llm,
    agent=AgentType.CONVERSATIONAL_REACT_DESCRIPTION,
    memory=memory,
    verbose=True,
    max_iterations=5,
    early_stopping_method="generate"
)

# 第七步：交互式界面
def interactive_mode():
    """
    交互式命令行界面
    """
    print("\n🔐 VulnSage - AI-Powered Security Code Review Agent")
    print("    Using Multi-Agent Architecture with LLM Reasoning")
    print("="*60)
    print("Available commands:")
    print("  - Just paste code to analyze it")
    print("  - 'compare': Compare two code snippets")
    print("  - 'fix': Get secure code suggestions")
    print("  - 'repo <path>': Analyze repository")
    print("  - 'help': Show this help")
    print("  - 'exit': Exit the program")
    print("="*60)
    
    while True:
        try:
            user_input = input("\n🤖 How can I help you with code security? > ").strip()
            
            if user_input.lower() == 'exit':
                print("👋 Goodbye!")
                break
            elif user_input.lower() == 'help':
                print("I can analyze code for security vulnerabilities using advanced AI reasoning.")
                print("Just paste your code or describe what you need!")
                continue
            elif user_input.lower() == 'compare':
                print("Paste the first code snippet (end with '---'):")
                code1 = []
                while True:
                    line = input()
                    if line.strip() == '---':
                        break
                    code1.append(line)
                
                print("\nPaste the second code snippet (end with '---'):")
                code2 = []
                while True:
                    line = input()
                    if line.strip() == '---':
                        break
                    code2.append(line)
                
                response = agent.run(f"比较这两段代码的安全性：\n\n代码1:\n{chr(10).join(code1)}\n\n代码2:\n{chr(10).join(code2)}")
                print(f"\n{response}")
                continue
            
            # 使用 Agent 处理输入
            response = agent.run(user_input)
            print(f"\n{response}")
            
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {str(e)}")

# 示例：展示 AI 的泛化能力
def demonstrate_ai_capabilities():
    """
    演示 AI 如何检测未在模式中定义的新型漏洞
    """
    print("\n🎯 Demonstrating AI's Generalization Capabilities\n")
    
    # 示例1：复杂的业务逻辑漏洞
    complex_code = """
def transfer_money(from_account, to_account, amount):
    # Check sender balance
    sender_balance = get_balance(from_account)
    
    if sender_balance >= amount:
        # Deduct from sender
        update_balance(from_account, sender_balance - amount)
        
        # Add to receiver  
        receiver_balance = get_balance(to_account)
        update_balance(to_account, receiver_balance + amount)
        
        return True
    return False
"""
    
    print("Example 1: Complex Business Logic")
    print("Code:")
    print(complex_code)
    print("\nAI Analysis:")
    print(analyze_code_with_ai(complex_code))
    
    # 示例2：新型注入攻击
    novel_injection = """
@app.route('/search')
def search():
    query = request.args.get('q')
    # Using new NoSQL database
    results = mongodb.products.find({"$where": f"this.name.match(/{query}/)"})
    return render_template('results.html', results=results)
"""
    
    print("\n" + "="*60 + "\n")
    print("Example 2: Novel Injection Pattern")
    print("Code:")
    print(novel_injection)
    print("\nAI Analysis:")
    print(analyze_code_with_ai(novel_injection))

# 主程序入口
if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--demo":
            # 演示 AI 能力
            demonstrate_ai_capabilities()
        elif sys.argv[1] == "--scan" and len(sys.argv) > 2:
            # 扫描文件
            with open(sys.argv[2], 'r') as f:
                code = f.read()
            print("🔍 Analyzing file with AI...\n")
            print(analyze_code_with_ai(code))
        elif sys.argv[1] == "--repo" and len(sys.argv) > 2:
            # 扫描仓库
            print("🔍 Analyzing repository with AI...\n")
            print(analyze_repository(sys.argv[2]))
        else:
            print("Usage:")
            print("  python agent.py                    # Interactive mode")
            print("  python agent.py --demo             # See AI capabilities demo")
            print("  python agent.py --scan <file>      # Scan a file")  
            print("  python agent.py --repo <path>      # Scan a repository")
    else:
        # 交互模式
        interactive_mode()
