type Line = {
	indent: number;
	text: string;
};

// small yaml reader for mock fixtures only
export function loadYaml<T>(source: string): T {
	const lines = source
		.split(/\r?\n/)
		.map((raw) => ({ indent: raw.search(/\S|$/), text: raw.trim() }))
		.filter((line) => line.text && !line.text.startsWith('#'));

	return readBlock(lines, 0, lines[0]?.indent ?? 0).value as T;
}

function readBlock(lines: Line[], index: number, indent: number): { value: unknown; next: number } {
	return lines[index]?.text.startsWith('- ')
		? readArray(lines, index, indent)
		: readObject(lines, index, indent);
}

// supports the list shapes in mock_data
function readArray(lines: Line[], index: number, indent: number): { value: unknown[]; next: number } {
	const value: unknown[] = [];

	while (index < lines.length && lines[index].indent === indent && lines[index].text.startsWith('- ')) {
		const item = lines[index].text.slice(2).trim();
		index += 1;

		if (!item) {
			const child = readBlock(lines, index, indent + 2);
			value.push(child.value);
			index = child.next;
		} else if (item.includes(':')) {
			const [key, scalar] = splitPair(item);
			const object: Record<string, unknown> = { [key]: scalar ? readScalar(scalar) : undefined };

			if (index < lines.length && lines[index].indent > indent) {
				const child = readObject(lines, index, indent + 2);
				Object.assign(object, child.value);
				index = child.next;
			}

			value.push(object);
		} else {
			value.push(readScalar(item));
		}
	}

	return { value, next: index };
}

function readObject(
	lines: Line[],
	index: number,
	indent: number
): { value: Record<string, unknown>; next: number } {
	const value: Record<string, unknown> = {};

	while (index < lines.length && lines[index].indent === indent && !lines[index].text.startsWith('- ')) {
		const [key, scalar] = splitPair(lines[index].text);
		index += 1;

		if (scalar) {
			value[key] = readScalar(scalar);
		} else {
			const child = readBlock(lines, index, indent + 2);
			value[key] = child.value;
			index = child.next;
		}
	}

	return { value, next: index };
}

// split only on the first colon
function splitPair(text: string): [string, string] {
	const splitAt = text.indexOf(':');
	return [text.slice(0, splitAt).trim(), text.slice(splitAt + 1).trim()];
}

function readScalar(value: string): unknown {
	if (value === 'true') return true;
	if (value === 'false') return false;
	if (value === 'null') return null;
	if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
	if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
		return value.slice(1, -1);
	}

	return value;
}
