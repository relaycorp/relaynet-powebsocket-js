export async function getPromiseRejection<ErrorType extends Error>(
  promise: Promise<any>,
): Promise<ErrorType> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected promise to throw');
}

export async function asyncIterableToArray<T>(iterable: AsyncIterable<T>): Promise<readonly T[]> {
  // tslint:disable-next-line:readonly-array
  const values = [];
  for await (const item of iterable) {
    values.push(item);
  }
  return values;
}

export async function* iterableTake<T>(iterable: AsyncIterable<T>, max: number): AsyncIterable<T> {
  if (max <= 0) {
    return;
  }

  let count = 0;
  for await (const item of iterable) {
    yield item;
    count++;
    if (max === count) {
      break;
    }
  }
}
