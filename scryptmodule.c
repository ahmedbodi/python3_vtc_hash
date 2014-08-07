#include <Python.h>

#include "scrypt.h"

static unsigned char getNfactor(char* blockheader) {
    int n,l = 0;
    
    // unpack timestamp from blockheader
    unsigned long nTimestamp = *(unsigned int*)(&blockheader[68]);
    unsigned char minNfactor = 10;
    unsigned char maxNfactor = 30;
    unsigned char N;
    uint64_t s;

    if (nTimestamp <= 1389306217) {
        return minNfactor;
    }

    s = nTimestamp - 1389306217;
    while ((s >> 1) > 3) {
      l += 1;
      s >>= 1;
    }

    s &= 3;

    n = (l * 158 + (int)s * 28 - 2670) / 100;

    if (n < 0) n = 0;

    N = (unsigned char) n;
    n = N > minNfactor ? N : minNfactor;
    N = n < maxNfactor ? n : maxNfactor;

    return N;
}

static PyObject *scrypt_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    unsigned char Nfactor;
    PyObject *value;
#if PY_MAJOR_VERSION >= 3
    PyBytesObject *input;
#else
    PyStringObject *input;
#endif
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;

    Py_INCREF(input);
    output = PyMem_Malloc(32);

#if PY_MAJOR_VERSION >= 3
    char *blockheader = (char *)PyBytes_AsString((PyObject*) input);
#else
    char *blockheader = (char *)PyString_AsString((PyObject*) input);
#endif

    Nfactor = getNfactor(blockheader);
    scrypt_N_sse2(blockheader, output, Nfactor);
    Py_DECREF(input);
#if PY_MAJOR_VERSION >= 3
    value = Py_BuildValue("y#", output, 32);
#else
    value = Py_BuildValue("s#", output, 32);
#endif
    PyMem_Free(output);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "getPoWHash", scrypt_getpowhash, METH_VARARGS, "Returns the proof of work hash using scrypt" },
    { NULL, NULL, 0, NULL }
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef ScryptModule = {
    PyModuleDef_HEAD_INIT,
    "vtc_scrypt",
    "...",
    -1,
    ScryptMethods
};

PyMODINIT_FUNC PyInit_vtc_scrypt(void) {
    return PyModule_Create(&ScryptModule);
}

#else

PyMODINIT_FUNC initvtc_scrypt(void) {
    (void) Py_InitModule("vtc_scrypt", ScryptMethods);
}
#endif
