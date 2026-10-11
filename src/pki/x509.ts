// X.509 2 requires Reflect metadata before its dependency-injection setup runs.
// All runtime consumers use this entry point, including independent PEM input.
import 'reflect-metadata';
export * from '@peculiar/x509';
