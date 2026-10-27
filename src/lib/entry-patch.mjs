// Only explicitly present fields are changed. Null is an intentional clear.
export function presencePatch(baseline, changes, present = Object.keys(changes)) {
  const patch = {};
  for (const key of present) {
    if (Object.hasOwn(changes, key) && changes[key] !== undefined && JSON.stringify(baseline?.[key]) !== JSON.stringify(changes[key])) patch[key] = changes[key];
  }
  return patch;
}
export function preservePayload(baseline, changes, present = Object.keys(changes)) {
  return { ...baseline, ...presencePatch(baseline, changes, present) };
}
export function storedOption(options, value) {
  return options.includes(value) ? options : [...options, value];
}