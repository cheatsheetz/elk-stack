# ELK Stack Cheat Sheet

## Installation (Docker Compose)
```yaml
# docker-compose.yml
version: '3.7'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    ports:
      - "5000:5000/tcp"
      - "5000:5000/udp"
      - "9600:9600"
    environment:
      - "LS_JAVA_OPTS=-Xms256m -Xmx256m"
    volumes:
      - ./logstash/pipeline:/usr/share/logstash/pipeline
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml
    depends_on:
      - elasticsearch

volumes:
  elasticsearch-data:
```

## Elasticsearch
```bash
# Basic operations
curl -X GET "localhost:9200/_cluster/health"
curl -X GET "localhost:9200/_cat/nodes?v"
curl -X GET "localhost:9200/_cat/indices?v"

# Index operations
curl -X PUT "localhost:9200/my_index"
curl -X DELETE "localhost:9200/my_index"

# Document operations
curl -X POST "localhost:9200/logs/_doc/" -H 'Content-Type: application/json' -d'
{
  "timestamp": "2023-12-01T10:00:00",
  "level": "INFO",
  "message": "Application started",
  "service": "web-app"
}'

# Search
curl -X GET "localhost:9200/logs/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "level": "ERROR"
    }
  }
}'

# Bulk operations
curl -X POST "localhost:9200/_bulk" -H 'Content-Type: application/json' -d'
{"index":{"_index":"logs","_id":"1"}}
{"timestamp":"2023-12-01T10:00:00","level":"INFO","message":"App started"}
{"index":{"_index":"logs","_id":"2"}}
{"timestamp":"2023-12-01T10:01:00","level":"ERROR","message":"Connection failed"}
'
```

## Logstash Configuration
```ruby
# /usr/share/logstash/pipeline/logstash.conf
input {
  beats {
    port => 5044
  }
  
  file {
    path => "/var/log/app.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
  
  http {
    port => 8080
  }
  
  syslog {
    port => 514
  }
}

filter {
  if [fields][type] == "nginx" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
    
    mutate {
      convert => { "response" => "integer" }
      convert => { "bytes" => "integer" }
    }
    
    if [response] >= 400 {
      mutate {
        add_tag => [ "error" ]
      }
    }
  }
  
  if [fields][type] == "application" {
    json {
      source => "message"
    }
    
    if "_jsonparsefailure" not in [tags] {
      mutate {
        remove_field => [ "message" ]
      }
    }
  }
  
  # Add GeoIP
  geoip {
    source => "clientip"
    target => "geoip"
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
  }
  
  if [level] == "ERROR" {
    email {
      to => "admin@company.com"
      subject => "Application Error"
      body => "Error occurred: %{message}"
    }
  }
  
  stdout {
    codec => rubydebug
  }
}
```

## Filebeat Configuration
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/nginx/access.log
  fields:
    type: nginx
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /var/log/app/application.log
  fields:
    type: application
  multiline.pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
  multiline.negate: true
  multiline.match: after

output.logstash:
  hosts: ["logstash:5044"]

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_docker_metadata: ~
- add_kubernetes_metadata: ~
```

## Kibana
```bash
# Index patterns
Management > Stack Management > Index Patterns > Create index pattern

# Search queries (KQL)
level:ERROR
response:>=400
@timestamp:[now-1h TO now]
message:"database connection"
NOT status:200

# Lucene query syntax
level:ERROR AND service:web-app
response:[400 TO 599]
message:/error|exception/
_exists_:user_id
```

## Index Templates
```json
PUT _template/logs-template
{
  "index_patterns": ["logs-*"],
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0,
    "index.refresh_interval": "5s"
  },
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      },
      "level": {
        "type": "keyword"
      },
      "message": {
        "type": "text",
        "analyzer": "standard"
      },
      "service": {
        "type": "keyword"
      },
      "response_time": {
        "type": "float"
      }
    }
  }
}
```

## Monitoring and Alerting
```bash
# Elasticsearch cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Index statistics
curl -X GET "localhost:9200/_stats?pretty"

# Node info
curl -X GET "localhost:9200/_nodes/stats?pretty"
```

## Common Patterns
```ruby
# Logstash grok patterns
%{TIMESTAMP_ISO8601:timestamp} \[%{LOGLEVEL:level}\] %{GREEDYDATA:message}
%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \[%{HTTPDATE:timestamp}\] "%{WORD:verb} %{DATA:request} HTTP/%{NUMBER:httpversion}" %{NUMBER:response} %{NUMBER:bytes}

# Custom pattern
(?<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?<level>\w+)\] (?<message>.*)
```

## Performance Tuning
```yaml
# Elasticsearch settings
cluster.name: my-cluster
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
bootstrap.memory_lock: true
network.host: 0.0.0.0
http.port: 9200
discovery.seed_hosts: ["127.0.0.1"]
cluster.initial_master_nodes: ["node-1"]

# JVM options
-Xms4g
-Xmx4g
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200
```

## Official Links
- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Elasticsearch Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Logstash Documentation](https://www.elastic.co/guide/en/logstash/current/index.html)
- [Kibana Guide](https://www.elastic.co/guide/en/kibana/current/index.html)