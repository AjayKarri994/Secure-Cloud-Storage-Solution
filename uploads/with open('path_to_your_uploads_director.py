with open('path_to_your_uploads_directory/your_filename', 'rb') as f:
    encrypted_content = f.read()
    print(encrypted_content)  # Should be unreadable binary data
