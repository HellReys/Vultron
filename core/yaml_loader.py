import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            return super().construct_mapping(node, deep=deep)

        self.flatten_mapping(node)
        seen = set()

        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)

            try:
                duplicate = key in seen
            except TypeError as error:
                raise ConstructorError(
                    None,
                    None,
                    "YAML mapping key must be hashable",
                    key_node.start_mark,
                ) from error

            if duplicate:
                raise ConstructorError(
                    None,
                    None,
                    f"Duplicate YAML key: {key!r}",
                    key_node.start_mark,
                )

            seen.add(key)

        return super().construct_mapping(node, deep=deep)


def load_yaml(file):
    """Load YAML safely and reject duplicate keys."""

    return yaml.load(file, Loader=UniqueKeySafeLoader)
