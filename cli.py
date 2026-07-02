import os
import sys
import time
from qdrant_client import QdrantClient
from groq import Groq

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from config import GROQ_API_KEY, GROQ_MODEL, COLLECTION_NAME, QDRANT_PATH, CVE_CACHE_FILE
from ingest import fetch_cves, parse_cve_records
from search import create_collection, ingest_documents, dense_search, sparse_search, hybrid_search

console = Console()


def print_header():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]🛡️  CVE-Intel: Hybrid RAG Search & Analysis[/bold cyan]\n"
        "[dim]Semantic (Dense) + Keyword (Sparse) Search over Security Vulnerabilities[/dim]",
        border_style="cyan"
    ))


def get_db_status(client):
    try:
        exists = client.collection_exists(collection_name=COLLECTION_NAME)
        if exists:
            info = client.get_collection(collection_name=COLLECTION_NAME)
            return exists, info.points_count
        return exists, 0
    except Exception:
        return False, 0


def print_status(client):
    exists, count = get_db_status(client)
    cache_exists = os.path.exists(CVE_CACHE_FILE)
    
    status_table = Table.grid(padding=(0, 2))
    status_table.add_column(style="bold blue")
    status_table.add_column()
    
    status_table.add_row("Database Status:", "[green]Active (Persistent)[/green]" if exists else "[yellow]Not Created[/yellow]")
    status_table.add_row("Stored CVE Records:", f"[bold cyan]{count}[/bold cyan]" if exists else "0")
    status_table.add_row("Cache File:", f"[green]Found ({CVE_CACHE_FILE})[/green]" if cache_exists else "[yellow]None[/yellow]")
    
    has_api_key = GROQ_API_KEY and GROQ_API_KEY != "your-api-key-here" and GROQ_API_KEY.startswith("gsk_")
    status_table.add_row("Groq LLM Status:", "[green]Connected (Ready)[/green]" if has_api_key else "[yellow]Missing API Key (Dry Run/Mock Mode Only)[/yellow]")
    
    console.print(Panel(
        status_table,
        title="[bold]System Status[/bold]",
        border_style="blue",
        expand=False
    ))


def perform_search(client):
    query = Prompt.ask("\n[bold yellow]Enter Search Query (e.g. 'remote code execution', CVE ID, etc.)[/bold yellow]")
    if not query.strip():
        return
        
    strategy = Prompt.ask(
        "Select Search Strategy",
        choices=["hybrid", "dense", "sparse"],
        default="hybrid"
    )
    
    severity = Prompt.ask(
        "Filter by Severity",
        choices=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="ALL"
    )
    
    min_cvss = Prompt.ask(
        "Filter by Minimum CVSS Score (0.0 to 10.0)",
        default="0.0"
    )
    try:
        min_cvss = float(min_cvss)
        if not (0.0 <= min_cvss <= 10.0):
            min_cvss = 0.0
    except ValueError:
        min_cvss = 0.0
        
    score_threshold = Prompt.ask(
        "Score threshold filter (e.g. 0.01 for RRF hybrid, or leave empty)",
        default=""
    )
    if score_threshold.strip():
        try:
            score_threshold = float(score_threshold)
        except ValueError:
            score_threshold = None
    else:
        score_threshold = None

    start_date = Prompt.ask(
        "Filter by Start Date (YYYY-MM-DD or leave empty)",
        default=""
    ).strip()
    if not start_date:
        start_date = None

    end_date = Prompt.ask(
        "Filter by End Date (YYYY-MM-DD or leave empty)",
        default=""
    ).strip()
    if not end_date:
        end_date = None

    limit = Prompt.ask("Max results to display", default="5")
    try:
        limit = int(limit)
    except ValueError:
        limit = 5
        
    severity_filter = None if severity == "ALL" else severity
    
    # Perform Search
    with console.status(f"[bold green]Searching using {strategy} strategy...[/bold green]"):
        if strategy == "dense":
            results = dense_search(client, query, limit=limit, severity_filter=severity_filter, min_cvss=min_cvss, score_threshold=score_threshold, start_date=start_date, end_date=end_date)
        elif strategy == "sparse":
            results = sparse_search(client, query, limit=limit, severity_filter=severity_filter, min_cvss=min_cvss, score_threshold=score_threshold, start_date=start_date, end_date=end_date)
        else:
            results = hybrid_search(client, query, limit=limit, severity_filter=severity_filter, min_cvss=min_cvss, score_threshold=score_threshold, start_date=start_date, end_date=end_date)
            
    if not results:
        console.print("[yellow]No matching vulnerability records found.[/yellow]")
        return
        
    # Render Results Table
    title_str = f"Search Results for: '{query}' (Strategy: {strategy}"
    if severity_filter:
        title_str += f", Severity: {severity_filter}"
    if min_cvss > 0.0:
        title_str += f", Min CVSS: {min_cvss:.1f}"
    if score_threshold is not None:
        title_str += f", Min Score: {score_threshold}"
    if start_date:
        title_str += f", Start: {start_date}"
    if end_date:
        title_str += f", End: {end_date}"
    title_str += ")"
    
    table = Table(title=title_str, expand=True)
    table.add_column("Score", justify="right", style="cyan", no_wrap=True)
    table.add_column("CVE ID", style="bold green", no_wrap=True)
    table.add_column("Severity", style="bold", no_wrap=True)
    table.add_column("CVSS", justify="right", style="magenta")
    table.add_column("Description", style="white")
    
    for r in results:
        payload = r.payload
        sev = payload.get("severity", "UNKNOWN")
        cvss = payload.get("cvss_score", 0.0)
        
        # Color severity
        if sev == "CRITICAL":
            sev_str = f"[bold red]{sev}[/bold red]"
        elif sev == "HIGH":
            sev_str = f"[bold orange3]{sev}[/bold orange3]"
        elif sev == "MEDIUM":
            sev_str = f"[bold yellow]{sev}[/bold yellow]"
        elif sev == "LOW":
            sev_str = f"[bold green]{sev}[/bold green]"
        else:
            sev_str = f"[bold grey37]{sev}[/bold grey37]"
            
        desc = payload.get("description", "")
        # Truncate description for readability
        if len(desc) > 150:
            desc = desc[:147] + "..."
            
        table.add_row(
            f"{r.score:.3f}",
            payload.get("cve_id", "UNKNOWN"),
            sev_str,
            f"{cvss:.1f}",
            desc
        )
        
    console.print(table)
    
    # Prompt for LLM Report
    if Confirm.ask("\nGenerate LLM Security Analysis report based on these results?"):
        generate_llm_report(query, results)


def generate_llm_report(query, results):
    has_api_key = GROQ_API_KEY and GROQ_API_KEY != "your-api-key-here" and GROQ_API_KEY.startswith("gsk_")
    
    if not has_api_key:
        console.print(Panel(
            "[bold red]❌ Groq API Key Missing or Invalid[/bold red]\n\n"
            "To generate real LLM analysis reports, please configure your [bold]GROQ_API_KEY[/bold] in a [bold].env[/bold] file.\n"
            "Example:\n"
            "  GROQ_API_KEY=gsk_...\n\n"
            "Showing mock report template below based on the retrieved context.",
            title="LLM Report Generator",
            border_style="red"
        ))
        
        # Show a mock summary
        mock_cves = ", ".join(r.payload.get("cve_id", "UNKNOWN") for r in results[:3])
        console.print(Panel(
            f"[bold cyan]🔍 Mock Vulnerability Analysis for Query: '{query}'[/bold cyan]\n\n"
            f"[bold]Summary:[/bold] Analysed results containing {len(results)} CVEs, including {mock_cves}.\n"
            f"[bold]Key Risks:[/bold] These vulnerabilities expose the system to attack surface issues corresponding to the user query.\n"
            f"[bold]Remediation Recommendations:[/bold] Update affected software packages to the latest patched releases.",
            title="Mock Analysis Report",
            border_style="yellow"
        ))
        return

    with console.status("[bold green]Contacting Groq LLM and generating report...[/bold green]"):
        try:
            groq_client = Groq(api_key=GROQ_API_KEY)
            
            # Format context
            context = "\n\n".join(
                f"- {doc.payload['cve_id']}: {doc.payload['description']} "
                f"(Severity: {doc.payload['severity']}, CVSS: {doc.payload['cvss_score']})"
                for doc in results
            )
            
            messages = [
                {
                    "role": "system",
                    "content": (
                        "You are an expert security analyst. Answer questions or generate analysis reports "
                        "based ONLY on the provided CVE context. If the context does not contain relevant information, "
                        "say so. Highlight key risks, CVSS scores, and cite CVE IDs in your response."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Context:\n{context}\n\nUser Query/Question: {query}\nPlease write a summary report detailing the critical risks and recommendations.",
                },
            ]
            
            response = groq_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=messages,
                temperature=0.1,
                max_tokens=600,
            )
            
            report = response.choices[0].message.content
            console.print(Panel(
                report,
                title=f"[bold green]🛡️ Groq LLM Security Report for Query: '{query}'[/bold green]",
                border_style="green",
                expand=False
            ))
        except Exception as e:
            console.print(f"[bold red]Error generating report from Groq API: {e}[/bold red]")


def handle_ingestion(client):
    console.print("\n[bold cyan]Database Management Options:[/bold cyan]")
    console.print("1. Force fetch & re-ingest latest CVEs from NVD (bypasses cache)")
    console.print("2. Re-ingest using cached CVEs (refresh database)")
    console.print("3. Clear cache file")
    console.print("4. Back to Main Menu")
    
    choice = Prompt.ask("Select option", choices=["1", "2", "3", "4"], default="4")
    
    if choice == "1":
        limit = Prompt.ask("Enter number of CVEs to fetch", default="50")
        try:
            limit = int(limit)
        except ValueError:
            limit = 50
        with console.status("[bold green]Fetching fresh data from NVD (this might take a few seconds)...[/bold green]"):
            try:
                raw_data = fetch_cves(results_per_page=limit, force_refresh=True)
                documents = parse_cve_records(raw_data)
                create_collection(client, force_recreate=True)
                ingest_documents(client, documents)
                console.print(f"[green]Successfully fetched and ingested {len(documents)} records into Qdrant.[/green]")
            except Exception as e:
                console.print(f"[bold red]Ingestion failed: {e}[/bold red]")
                
    elif choice == "2":
        if not os.path.exists(CVE_CACHE_FILE):
            console.print("[yellow]No local cache file found. Please fetch from NVD first.[/yellow]")
            return
        with console.status("[bold green]Loading from cache and ingesting into Qdrant...[/bold green]"):
            try:
                raw_data = fetch_cves(force_refresh=False)
                documents = parse_cve_records(raw_data)
                create_collection(client, force_recreate=True)
                ingest_documents(client, documents)
                console.print(f"[green]Successfully re-ingested {len(documents)} records from local cache.[/green]")
            except Exception as e:
                console.print(f"[bold red]Ingestion failed: {e}[/bold red]")
                
    elif choice == "3":
        if os.path.exists(CVE_CACHE_FILE):
            try:
                os.remove(CVE_CACHE_FILE)
                console.print(f"[green]Deleted cache file: {CVE_CACHE_FILE}[/green]")
            except Exception as e:
                console.print(f"[bold red]Failed to delete cache file: {e}[/bold red]")
        else:
            console.print("[yellow]Cache file does not exist.[/yellow]")


def main():
    # Initialize Qdrant Client
    client = QdrantClient(path=QDRANT_PATH)
    
    # Auto-initialize on first startup if database is empty
    exists, count = get_db_status(client)
    if not exists or count == 0:
        console.print("[yellow]No CVE database found. Initializing database with first ingestion...[/yellow]")
        try:
            raw_data = fetch_cves(50)
            documents = parse_cve_records(raw_data)
            create_collection(client, force_recreate=True)
            ingest_documents(client, documents)
            console.print("[green]Database initialized successfully![/green]\n")
            time.sleep(1.5)
        except Exception as e:
            console.print(f"[bold red]Failed to initialize database: {e}[/bold red]")
            console.print("[yellow]Starting CLI anyway, database operations may fail until initialized.[/yellow]")
            time.sleep(2)
            
    while True:
        print_header()
        print_status(client)
        
        console.print("\n[bold cyan]What would you like to do?[/bold cyan]")
        console.print("1. [bold green]🔍 Interactive Search & LLM Analysis[/bold green]")
        console.print("2. [bold blue]⚙️  Database & Cache Management[/bold blue]")
        console.print("3. [bold red]❌ Exit[/bold red]")
        
        choice = Prompt.ask("Enter selection", choices=["1", "2", "3"], default="1")
        
        if choice == "1":
            try:
                perform_search(client)
            except Exception as e:
                console.print(f"[bold red]Search error: {e}[/bold red]")
            Prompt.ask("\nPress Enter to return to main menu...")
        elif choice == "2":
            try:
                handle_ingestion(client)
            except Exception as e:
                console.print(f"[bold red]Management error: {e}[/bold red]")
            Prompt.ask("\nPress Enter to return to main menu...")
        elif choice == "3":
            console.print("\n[bold cyan]Thank you for using CVE-Intel! Goodbye.[/bold cyan]")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[bold cyan]CLI execution terminated by user. Goodbye![/bold cyan]")
        sys.exit(0)
