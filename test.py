import json

from moz_sql_parser import parse


class SQLToESConverter:
    def __init__(self, sql: str):
        self.index = None
        self.sql = sql
        self.parsed = parse(sql)
        self.dsl = {}

        print(self.parsed)

    def get_dsl(self, indent: int = 2):
        return json.dumps(self.dsl, indent=indent)

    def convert(self) -> 'SQLToESConverter':
        self.dsl = {}

        if 'select' in self.parsed:
            self.dsl['_source'] = self._parse_select(self.parsed['select'])

        if 'from' in self.parsed:
            self.index = self.parsed['from']

        if 'where' in self.parsed:
            self.dsl['query'] = self._parse_where(self.parsed['where'])

        if 'orderby' in self.parsed:
            self.dsl['sort'] = self._parse_order_by(self.parsed['orderby'])

        if 'limit' in self.parsed:
            self.dsl['size'] = self.parsed['limit']

        return self

    @staticmethod
    def _parse_select(select) -> list:
        fields = []
        if isinstance(select, list):
            for item in select:
                value = item.get('value')
                if isinstance(value, str):
                    # 形如：{"name": "alias"}
                    fields.append(value)
        elif isinstance(select, dict):
            fields.append(select.get('value'))
        return fields

    def _parse_where(self, where):
        return self._parse_where_logic(where)

    @staticmethod
    def _parse_order_by(order) -> list:
        if isinstance(order, list):
            return [{o['value']: {'order': o.get('sort', 'asc')}} for o in order]
        else:
            return [{order['value']: {'order': order.get('sort', 'asc')}}]

    def _parse_where_logic(self, expr):
        if isinstance(expr, str):
            # 支持 NOT is_admin => { "term": { "is_admin": true } }
            return {'term': {expr: True}}

        if isinstance(expr, dict):
            if 'and' in expr:
                return {'bool': {'must': [self._parse_where_logic(e) for e in expr['and']]}}
            elif 'or' in expr:
                return {'bool': {'should': [self._parse_where_logic(e) for e in expr['or']]}}
            elif 'not' in expr:
                return {'bool': {'must_not': [self._parse_where_logic(expr['not'])]}}

            # 通用比较操作符
            comparison_ops = {
                '=': lambda f, v: {'term': {'eq': v['literal']}},
                '==': lambda f, v: {'term': {'eq': v}},
                '!=': lambda f, v: {'bool': {'must_not': [{'term': {'eq': v}}]}},
                '<>': lambda f, v: {'bool': {'must_not': [{'term': {'eq': v}}]}},
                '>': lambda f, v: {'range': {f: {'gt': v}}},
                '<': lambda f, v: {'range': {f: {'lt': v}}},
                '>=': lambda f, v: {'range': {f: {'gte': v}}},
                '<=': lambda f, v: {'range': {f: {'lte': v}}},
                'gt': lambda f, v: {'range': {f: {'gt': v}}},
                'lt': lambda f, v: {'range': {f: {'lt': v}}},
                'gte': lambda f, v: {'range': {f: {'gte': v}}},
                'lte': lambda f, v: {'range': {f: {'lte': v}}},
                'eq': lambda f, v: {'bool': {'must': [{'term': {f: v['literal']}}]}},
                'neq': lambda f, v: {'bool': {'must_not': [{'term': {'eq': v}}]}}
            }

            for op, handler in comparison_ops.items():
                if op in expr:
                    field, value = expr[op]
                    return handler(field, value)

        raise ValueError("Unsupported expression: " + str(expr))


sql = """
SELECT name, age FROM users
WHERE (age > 30 AND city = 'Beijing') OR (status = 'active' AND NOT is_admin)
ORDER BY name DESC LIMIT 10;
"""

sql2 = """
SELECT name FROM users
WHERE (age > 30 AND city = 'Beijing') OR (status = 'active' AND NOT is_admin)
ORDER BY name DESC LIMIT 10;
"""

sql3 = """
SELECT agentId, fileName FROM lingjing_dataset_medical_offline_index
WHERE sourceType in ('a', 'b')
LIMIT 1;
"""

converter = SQLToESConverter(sql3).convert()
print(converter.get_dsl())
