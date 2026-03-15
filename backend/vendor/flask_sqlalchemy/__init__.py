"""
Flask-SQLAlchemy shim using sqlite3.
Implements a minimal ORM that supports the exact query patterns used by Secure Lens AI.
"""

import os
import re
import sqlite3
import threading
from datetime import datetime

_db_local = threading.local()


# ---------------------------------------------------------------------------
# Column types (used in model definitions)
# ---------------------------------------------------------------------------

class _ColumnType:
    sql_type = "TEXT"


class Integer(_ColumnType):
    sql_type = "INTEGER"


class String(_ColumnType):
    def __init__(self, length=255):
        self.length = length
        self.sql_type = f"TEXT"


class Text(_ColumnType):
    sql_type = "TEXT"


class Float(_ColumnType):
    sql_type = "REAL"


class DateTime(_ColumnType):
    sql_type = "TEXT"


class Boolean(_ColumnType):
    sql_type = "INTEGER"


# ---------------------------------------------------------------------------
# Column definition
# ---------------------------------------------------------------------------

class Column:
    """Represents a database column."""

    def __init__(self, *args, **kwargs):
        # Parse positional args: Column(name_str, Type) or Column(Type) or Column(Type, ForeignKey(...))
        self.name = None  # Set later by metaclass
        self.type = None
        self.primary_key = kwargs.get("primary_key", False)
        self.unique = kwargs.get("unique", False)
        self.nullable = kwargs.get("nullable", True)
        self.default = kwargs.get("default", None)
        self.index = kwargs.get("index", False)
        self._foreign_key = None

        for arg in args:
            if isinstance(arg, str):
                self.name = arg
            elif isinstance(arg, type) and issubclass(arg, _ColumnType):
                self.type = arg()
            elif isinstance(arg, _ColumnType):
                self.type = arg
            elif isinstance(arg, ForeignKey):
                self._foreign_key = arg

        if self.type is None:
            self.type = Text()

    @property
    def sql_type(self):
        return self.type.sql_type if self.type else "TEXT"

    # Support query expressions like Model.column_name == value
    def __eq__(self, other):
        if isinstance(other, Column):
            return NotImplemented
        return _FilterExpr(self, "=", other)

    def __ne__(self, other):
        return _FilterExpr(self, "!=", other)

    def __gt__(self, other):
        return _FilterExpr(self, ">", other)

    def __lt__(self, other):
        return _FilterExpr(self, "<", other)

    def __ge__(self, other):
        return _FilterExpr(self, ">=", other)

    def __le__(self, other):
        return _FilterExpr(self, "<=", other)

    def desc(self):
        return _OrderExpr(self, "DESC")

    def asc(self):
        return _OrderExpr(self, "ASC")


class ForeignKey:
    def __init__(self, ref):
        self.ref = ref  # e.g., "users.id"


class _FilterExpr:
    """A filter expression for WHERE clauses."""
    def __init__(self, column, op, value):
        self.column = column
        self.op = op
        self.value = value


class _OrderExpr:
    """An ordering expression."""
    def __init__(self, column, direction):
        self.column = column
        self.direction = direction


# ---------------------------------------------------------------------------
# Relationships
# ---------------------------------------------------------------------------

def relationship(model_name, **kwargs):
    """Define a relationship (resolved lazily)."""
    return _RelationshipDef(model_name, **kwargs)


class _RelationshipDef:
    def __init__(self, model_name, **kwargs):
        self.model_name = model_name
        self.uselist = kwargs.get("uselist", True)
        self.backref = kwargs.get("backref", None)
        self.lazy = kwargs.get("lazy", True)
        self.cascade = kwargs.get("cascade", "")
        self.attr_name = None  # Set by metaclass
        self._owner_class = None  # Set by metaclass

    def __set_name__(self, owner, name):
        self.attr_name = name
        self._owner_class = owner

    def __get__(self, obj, objtype=None):
        """Lazy-load related objects when accessed on an instance."""
        if obj is None:
            return self  # Class-level access returns the descriptor

        # Find the related model class
        related_model = _ModelMeta._registry.get(self.model_name)
        if not related_model:
            return [] if self.uselist else None

        # Find the foreign key that links the two models
        # Case 1: This model has FK to related (e.g., UploadedFile.user_id → User)
        # Case 2: Related model has FK to this model (e.g., AnalysisResult.file_id → UploadedFile)
        owner_class = objtype or type(obj)
        owner_table = owner_class.__tablename__
        related_table = related_model.__tablename__

        # Check if related model has a FK pointing to owner
        for col_name, col_def in related_model._columns.items():
            if col_def._foreign_key and col_def._foreign_key.ref.startswith(owner_table + "."):
                ref_col = col_def._foreign_key.ref.split(".")[1]
                owner_id = getattr(obj, ref_col, None)
                if owner_id is not None:
                    # Query related model
                    q = _Query(related_model, _get_db_for_model(related_model))
                    q = q.filter_by(**{col_name: owner_id})
                    if self.uselist:
                        return q.all()
                    else:
                        return q.first()

        # Check if owner model has a FK pointing to related
        for col_name, col_def in owner_class._columns.items():
            if col_def._foreign_key and col_def._foreign_key.ref.startswith(related_table + "."):
                fk_val = getattr(obj, col_name, None)
                if fk_val is not None:
                    ref_col = col_def._foreign_key.ref.split(".")[1]
                    q = _Query(related_model, _get_db_for_model(related_model))
                    q = q.filter_by(**{ref_col: fk_val})
                    if self.uselist:
                        return q.all()
                    else:
                        return q.first()

        return [] if self.uselist else None


_global_db_ref = None  # Set when SQLAlchemy is instantiated

def _get_db_for_model(model_class):
    """Get the db instance for a model."""
    return _global_db_ref


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------

class _Query:
    """SQLite-backed query builder mimicking SQLAlchemy's Query API."""

    def __init__(self, model_class, db_instance):
        self._model = model_class
        self._db = db_instance
        self._filters = {}
        self._filter_exprs = []
        self._order_by = []
        self._joins = []
        self._limit = None
        self._offset = None

    def filter_by(self, **kwargs):
        q = self._clone()
        q._filters.update(kwargs)
        return q

    def filter(self, *exprs):
        q = self._clone()
        for expr in exprs:
            if isinstance(expr, _FilterExpr):
                q._filter_exprs.append(expr)
        return q

    def join(self, model_class):
        q = self._clone()
        q._joins.append(model_class)
        return q

    def order_by(self, *args):
        q = self._clone()
        for arg in args:
            if isinstance(arg, _OrderExpr):
                q._order_by.append(arg)
            elif isinstance(arg, Column):
                q._order_by.append(_OrderExpr(arg, "ASC"))
        return q

    def get(self, id_val):
        """Get by primary key."""
        conn = self._db._get_conn()
        table = self._model.__tablename__
        cursor = conn.execute(f"SELECT * FROM {table} WHERE id = ?", (id_val,))
        row = cursor.fetchone()
        if row:
            return self._row_to_model(row)
        return None

    def first(self):
        """Get first result."""
        conn = self._db._get_conn()
        sql, params = self._build_sql()
        sql += " LIMIT 1"
        cursor = conn.execute(sql, params)
        row = cursor.fetchone()
        if row:
            return self._row_to_model(row)
        return None

    def all(self):
        """Get all results."""
        conn = self._db._get_conn()
        sql, params = self._build_sql()
        if self._limit:
            sql += f" LIMIT {self._limit}"
        if self._offset:
            sql += f" OFFSET {self._offset}"
        cursor = conn.execute(sql, params)
        return [self._row_to_model(row) for row in cursor.fetchall()]

    def count(self):
        """Count results."""
        conn = self._db._get_conn()
        sql, params = self._build_sql(count=True)
        cursor = conn.execute(sql, params)
        row = cursor.fetchone()
        return row[0] if row else 0

    def paginate(self, page=1, per_page=20, error_out=True):
        """Paginate results."""
        total = self.count()
        q = self._clone()
        q._limit = per_page
        q._offset = (page - 1) * per_page
        items = q.all()

        return _Pagination(items, page, per_page, total)

    def _build_sql(self, count=False):
        """Build SQL query string."""
        table = self._model.__tablename__
        if count:
            select = f"SELECT COUNT(*) FROM {table}"
        else:
            select = f"SELECT {table}.* FROM {table}"

        # Joins
        for join_model in self._joins:
            jtable = join_model.__tablename__
            # Find the foreign key relationship
            fk_col = None
            for col_name, col_def in self._model._columns.items():
                if col_def._foreign_key and col_def._foreign_key.ref.startswith(jtable + "."):
                    fk_col = (col_name, col_def._foreign_key.ref)
                    break
            if not fk_col:
                for col_name, col_def in join_model._columns.items():
                    if col_def._foreign_key and col_def._foreign_key.ref.startswith(table + "."):
                        fk_col = (f"{jtable}.{col_name}", f"{table}.{col_def._foreign_key.ref.split('.')[1]}")
                        break
            if fk_col:
                select += f" JOIN {jtable} ON {table}.{fk_col[0]} = {fk_col[1]}"
            else:
                select += f" JOIN {jtable}"

        wheres = []
        params = []

        # filter_by (simple equality)
        for key, val in self._filters.items():
            wheres.append(f"{table}.{key} = ?")
            params.append(val)

        # filter expressions
        for expr in self._filter_exprs:
            col_name = expr.column.name
            # Determine which table the column belongs to
            col_table = table
            for join_model in self._joins:
                if col_name in join_model._columns:
                    col_table = join_model.__tablename__
                    break
            wheres.append(f"{col_table}.{col_name} {expr.op} ?")
            params.append(expr.value)

        sql = select
        if wheres:
            sql += " WHERE " + " AND ".join(wheres)

        # Order by
        if self._order_by and not count:
            orders = []
            for o in self._order_by:
                orders.append(f"{table}.{o.column.name} {o.direction}")
            sql += " ORDER BY " + ", ".join(orders)

        return sql, params

    def _row_to_model(self, row):
        """Convert a sqlite3.Row to a model instance."""
        obj = self._model.__new__(self._model)
        obj._db = self._db
        col_defs = getattr(self._model, '_columns', {})
        columns = row.keys()
        for col in columns:
            val = row[col]
            # Convert ISO datetime strings back to datetime objects for DateTime columns
            if col in col_defs and isinstance(col_defs[col].type, DateTime) and isinstance(val, str):
                try:
                    val = datetime.fromisoformat(val)
                except (ValueError, TypeError):
                    pass
            setattr(obj, col, val)
        return obj

    def _clone(self):
        q = _Query(self._model, self._db)
        q._filters = dict(self._filters)
        q._filter_exprs = list(self._filter_exprs)
        q._order_by = list(self._order_by)
        q._joins = list(self._joins)
        q._limit = self._limit
        q._offset = self._offset
        return q


class _Pagination:
    """Pagination result object."""

    def __init__(self, items, page, per_page, total):
        self.items = items
        self.page = page
        self.per_page = per_page
        self.total = total
        self.pages = max(1, (total + per_page - 1) // per_page)
        self.has_next = page < self.pages
        self.has_prev = page > 1


# ---------------------------------------------------------------------------
# Model metaclass
# ---------------------------------------------------------------------------

class _ModelMeta(type):
    """Metaclass for Model that extracts column definitions."""

    _registry = {}

    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)

        if name == "Model" and not bases:
            return cls

        # Extract columns
        columns = {}
        relationships = {}
        for key, val in list(namespace.items()):
            if isinstance(val, Column):
                val.name = val.name or key
                columns[key] = val
            elif isinstance(val, _RelationshipDef):
                val.attr_name = key
                relationships[key] = val

        cls._columns = columns
        cls._relationships = relationships
        cls._table_created = False

        # Register model
        if hasattr(cls, "__tablename__"):
            _ModelMeta._registry[name] = cls

        return cls


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class _Session:
    """Database session that wraps sqlite3 operations."""

    def __init__(self, db_instance):
        self._db = db_instance
        self._pending = []
        self._tracked = []  # Objects that have been committed (for dirty tracking)

    def add(self, obj):
        self._pending.append(("add", obj))

    def commit(self):
        conn = self._db._get_conn()
        for op, obj in self._pending:
            if op == "add":
                # Check if object already has a PK → update, else insert
                model_cls = type(obj)
                pk_col = None
                pk_val = None
                for col_name, col_def in model_cls._columns.items():
                    if col_def.primary_key:
                        pk_col = col_name
                        pk_val = getattr(obj, col_name, None)
                        break

                if pk_val is not None and not isinstance(pk_val, Column):
                    # Check if it exists in DB
                    existing = conn.execute(
                        f"SELECT {pk_col} FROM {model_cls.__tablename__} WHERE {pk_col} = ?",
                        (pk_val,)
                    ).fetchone()
                    if existing:
                        self._update(conn, obj)
                        continue
                self._insert(conn, obj)
        # Update any previously tracked objects that may have been modified
        for obj in self._tracked:
            model_cls = type(obj)
            if hasattr(model_cls, '_columns'):
                pk_val = None
                for cn, cd in model_cls._columns.items():
                    if cd.primary_key:
                        pk_val = getattr(obj, cn, None)
                        break
                if pk_val and not isinstance(pk_val, Column):
                    self._update(conn, obj)

        conn.commit()
        # Track newly added objects for future dirty detection
        for op, obj in self._pending:
            if op == "add" and obj not in self._tracked:
                self._tracked.append(obj)
        self._pending = []

    def rollback(self):
        conn = self._db._get_conn()
        conn.rollback()
        self._pending = []

    def _update(self, conn, obj):
        """Update an existing record."""
        model_cls = type(obj)
        table = model_cls.__tablename__
        columns = model_cls._columns

        pk_col = None
        pk_val = None
        sets = []
        values = []

        for col_name, col_def in columns.items():
            val = getattr(obj, col_name, None)
            if isinstance(val, Column):
                continue
            if col_def.primary_key:
                pk_col = col_name
                pk_val = val
                continue
            if isinstance(val, datetime):
                val = val.isoformat()
            sets.append(f"{col_name} = ?")
            values.append(val)

        if pk_col and pk_val and sets:
            values.append(pk_val)
            sql = f"UPDATE {table} SET {', '.join(sets)} WHERE {pk_col} = ?"
            conn.execute(sql, values)

    def _insert(self, conn, obj):
        model_cls = type(obj)
        table = model_cls.__tablename__
        columns = model_cls._columns

        col_names = []
        values = []
        for col_name, col_def in columns.items():
            val = getattr(obj, col_name, None)

            # Skip Column objects (class-level descriptor leaked through)
            if isinstance(val, Column):
                val = None

            if col_def.primary_key:
                if val is not None:
                    col_names.append(col_name)
                    values.append(val)
                continue  # Skip auto-increment PK if None

            # Apply defaults
            if val is None and col_def.default is not None:
                if callable(col_def.default):
                    val = col_def.default()
                else:
                    val = col_def.default
                # Also set on the object so it's available after insert
                setattr(obj, col_name, val)

            # Convert datetime to string for sqlite storage, but keep datetime on object
            sql_val = val
            if isinstance(val, datetime):
                sql_val = val.isoformat()
                # Don't overwrite the object's datetime with string

            col_names.append(col_name)
            values.append(sql_val)

        placeholders = ", ".join(["?"] * len(col_names))
        sql = f"INSERT INTO {table} ({', '.join(col_names)}) VALUES ({placeholders})"
        cursor = conn.execute(sql, values)

        # Set the auto-generated ID
        if cursor.lastrowid:
            for col_name, col_def in columns.items():
                if col_def.primary_key:
                    setattr(obj, col_name, cursor.lastrowid)
                    break


# ---------------------------------------------------------------------------
# SQLAlchemy main class
# ---------------------------------------------------------------------------

class SQLAlchemy:
    """Flask-SQLAlchemy compatible database manager."""

    # Expose column types
    Integer = Integer
    String = String
    Text = Text
    Float = Float
    DateTime = DateTime
    Boolean = Boolean
    Column = Column
    Model = None  # Set per-instance

    def __init__(self, app=None):
        global _global_db_ref
        self.app = app
        self._db_path = None
        self._connections = {}
        _global_db_ref = self

        # Create a Model base class with this db instance
        db_ref = self

        class Model(metaclass=_ModelMeta):
            _db = None

            def __init__(self, **kwargs):
                """Accept keyword arguments matching column names."""
                # Initialize all columns to None first (clears class-level Column descriptors)
                if hasattr(type(self), '_columns'):
                    for col_name in type(self)._columns:
                        if col_name not in kwargs:
                            setattr(self, col_name, None)
                # Set provided values
                for key, value in kwargs.items():
                    setattr(self, key, value)

            @classmethod
            def _get_query(cls):
                return _Query(cls, db_ref)

            query = property(lambda self: type(self)._get_query())

            def __init_subclass__(cls, **kwargs):
                super().__init_subclass__(**kwargs)
                cls.query = _QueryDescriptor(cls, db_ref)

        self.Model = Model
        self.session = _Session(self)
        self.relationship = relationship  # Function, not wrapped in staticmethod
        self.ForeignKey = ForeignKey

    def init_app(self, app):
        self.app = app
        db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "sqlite:///app.db")
        if db_uri.startswith("sqlite:///"):
            self._db_path = db_uri[len("sqlite:///"):]
        elif db_uri.startswith("sqlite://"):
            self._db_path = db_uri[len("sqlite://"):]
        else:
            self._db_path = "app.db"

        # Make path absolute if relative
        if not os.path.isabs(self._db_path) and self._db_path != ":memory:":
            # Use the backend directory as base
            import inspect
            frame = inspect.stack()
            for f in frame:
                if "app.py" in f.filename or "run.py" in f.filename:
                    base = os.path.dirname(os.path.abspath(f.filename))
                    self._db_path = os.path.join(base, self._db_path)
                    break

    def _get_conn(self):
        tid = threading.current_thread().ident
        if tid not in self._connections or self._connections[tid] is None:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._connections[tid] = conn
        return self._connections[tid]

    def create_all(self):
        """Create all registered tables."""
        conn = self._get_conn()
        for name, model_cls in _ModelMeta._registry.items():
            if not hasattr(model_cls, "__tablename__"):
                continue
            table = model_cls.__tablename__
            cols = []
            for col_name, col_def in model_cls._columns.items():
                parts = [col_name, col_def.sql_type]
                if col_def.primary_key:
                    parts.append("PRIMARY KEY AUTOINCREMENT" if isinstance(col_def.type, Integer) else "PRIMARY KEY")
                if col_def.unique and not col_def.primary_key:
                    parts.append("UNIQUE")
                if not col_def.nullable and not col_def.primary_key:
                    parts.append("NOT NULL")
                if col_def._foreign_key:
                    ref_table, ref_col = col_def._foreign_key.ref.split(".")
                    parts.append(f"REFERENCES {ref_table}({ref_col})")
                cols.append(" ".join(parts))

            sql = f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols)})"
            conn.execute(sql)
        conn.commit()

        # Resolve backrefs: if model A defines relationship("B", backref="a"),
        # then model B gets a reverse _RelationshipDef pointing to A.
        for name, model_cls in _ModelMeta._registry.items():
            for attr_name, rel in list(getattr(model_cls, '_relationships', {}).items()):
                if rel.backref:
                    target_model = _ModelMeta._registry.get(rel.model_name)
                    if target_model and not hasattr(target_model, rel.backref):
                        # Create reverse relationship
                        reverse = _RelationshipDef(name, uselist=False)
                        reverse.attr_name = rel.backref
                        reverse._owner_class = target_model
                        setattr(target_model, rel.backref, reverse)
                        if not hasattr(target_model, '_relationships'):
                            target_model._relationships = {}
                        target_model._relationships[rel.backref] = reverse


class _QueryDescriptor:
    """Descriptor that returns a Query for the model class."""

    def __init__(self, model_cls, db_instance):
        self._model = model_cls
        self._db = db_instance

    def __get__(self, obj, objtype=None):
        return _Query(objtype or self._model, self._db)

    # Make it callable for class-level access like Model.query.filter_by(...)
    def filter_by(self, **kwargs):
        return _Query(self._model, self._db).filter_by(**kwargs)

    def filter(self, *args):
        return _Query(self._model, self._db).filter(*args)

    def get(self, id_val):
        return _Query(self._model, self._db).get(id_val)

    def join(self, model):
        return _Query(self._model, self._db).join(model)

    def first(self):
        return _Query(self._model, self._db).first()

    def all(self):
        return _Query(self._model, self._db).all()

    def count(self):
        return _Query(self._model, self._db).count()

    def order_by(self, *args):
        return _Query(self._model, self._db).order_by(*args)

    def paginate(self, **kwargs):
        return _Query(self._model, self._db).paginate(**kwargs)
