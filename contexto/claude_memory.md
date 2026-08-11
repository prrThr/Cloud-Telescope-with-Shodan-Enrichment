### Purpose & context
Arthur is developing "Cloud Telescope," a network traffic analysis pipeline, as part of his undergraduate thesis (TCC). The project processes pcap files through an ETL pipeline, applying geographic and technical enrichment to network traffic data. The thesis formalizes this work with defined functional requirements (RF01–RF07), non-functional requirements (RNF01–RNF05), and use cases (CSU01–CSU03).

Key domain areas: network traffic analysis, packet capture processing, API integration, data enrichment, graph databases, and academic research presentation.

### Current state

The pipeline (ibr-etl) has been recently reorganized for portability and replicability:

- Pipeline scripts moved to src/, datasets to datasets/, Docker files to Docker/
- All scripts standardized to derive PROJECT_ROOT from their own file path (via os.path.dirname pattern), eliminating dependency on working directory or cd commands
- A Shodan enrichment module (src/6_shodan_enrich.py) has been built and validated, extending the enriched CSV with 10 Shodan-derived fields (organization, ISP, ASN, OS, open ports, CPEs, CVEs, tags, hostnames, last-seen)

The pipeline flow is: 1_generate_tshark_csv.sh → 2_enrich_csv.py → 6_shodan_enrich.py → parallel consumers (3_summarize_radiation.py, 4_generate_graph.py, 5_import_mysql.py) → comparative visualizations. Steps 3–5 consume the same enriched CSV in parallel rather than sequentially.

A hardcoded API key was identified as a security issue to address.

### On the horizon

- Comparative informational gain visualizations (planned final pipeline stage)
- Potentially a branching pipeline diagram to better represent the parallel nature of steps 3–5
- Full implementation of all thesis requirements beyond the current Shodan foundation

### Key learnings & principles

- Scripts must resolve paths relative to project root, not the working directory, to ensure cross-machine replicability
- Shodan API credit conservation is a real constraint: caching by IP (local JSON) and rate limiting (1 req/sec default, with 429 backoff) are essential design decisions, not optional
- The pipeline follows a consistent stdin/stdout CSV pattern across scripts, which should be preserved for new modules
Redundant scripts (e.g., duplicate Shodan enrichment) should be consolidated rather than maintained in parallel

### Tools & resources

- Core stack: Python, Bash, tshark (packet extraction), GeoLite2-City (GeoIP), Shodan API, Neo4j (Cypher graph), MySQL
- Infrastructure: Docker / docker-compose
- Data formats: pcap → CSV → enriched CSV (.rich.csv.gz, .shodan.gz) → Neo4j / MySQL
- Thesis document: TCC_2.pdf used as living specification for development alignment