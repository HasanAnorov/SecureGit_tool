import diff_match_patch as dmp_module

def create_patch(text1, text2):
    dmp = dmp_module.diff_match_patch()
    diffs = dmp.diff_main(text1, text2)
    dmp.diff_cleanupSemantic(diffs)
    patch = dmp.patch_make(text1, diffs)
    return patch

def apply_patch(text, patch):
    dmp = dmp_module.diff_match_patch()
    result, success = dmp.patch_apply(patch, text)
    return result

def serialize_patch(patch):
    dmp = dmp_module.diff_match_patch()
    patch_text = dmp.patch_toText(patch)
    return patch_text

def deserialize_patch(patch_text):
    dmp = dmp_module.diff_match_patch()
    patch = dmp.patch_fromText(patch_text)
    return patch


def test():
    text1 = b'''123445\n124\n123'''.decode()
    text2 = b'''1234\n'''.decode()
    patch = create_patch(text1, text2)
    serialized_patch = serialize_patch(patch)
    print("Serialized Patch:", serialized_patch)
    deserialized_patch = deserialize_patch(serialized_patch)
    resulting_text = apply_patch(text1, deserialized_patch)
    print("Text after applying deserialized patch:", resulting_text)


def test_file(origin_path, new_path):
    with open(origin_path, 'rb') as f:
        origin_data = f.read()
    with open(new_path, 'rb') as f:
        new_data = f.read()
    origin_data = origin_data.decode()
    new_data = new_data.decode()
    patch = create_patch(origin_data, new_data)
    serialized_patch = serialize_patch(patch)
    final_text = origin_data + '\n' + serialized_patch
    with open(new_path + '.diff', 'wb') as f:
        f.write(final_text.encode())


if __name__ == '__main__':
    test()

