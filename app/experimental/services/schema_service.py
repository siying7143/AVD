from pathlib import Path


class SchemaService:
    def __init__(self, connection):
        self.connection = connection

    def ensure_schema(self, schema_path: Path) -> None:
        # Execute each SQL statement from the schema file to create missing experimental tables.
        sql_text = schema_path.read_text(encoding="utf-8")
        statements = [statement.strip() for statement in sql_text.split(";") if statement.strip()]
        with self.connection.cursor() as cursor:
            for statement in statements:
                cursor.execute(statement)
        self.connection.commit()
