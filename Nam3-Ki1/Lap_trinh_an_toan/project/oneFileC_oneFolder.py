import os
import shutil


def list_files_and_create_directories(directory, destination_base):
    if not os.path.exists(directory):
        print(f"'{directory}' not found")
        return

    if not os.path.exists(destination_base):
        os.makedirs(destination_base)

    folder_count = 1

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)

        if os.path.isfile(filepath):
            folder_name = str(folder_count)
            destination_dir = os.path.join(destination_base, folder_name)

            if not os.path.exists(destination_dir):
                os.makedirs(destination_dir)

            destination_path = os.path.join(destination_dir, filename)
            shutil.copy2(filepath, destination_path)

            print(f"Copy '{filename}' to '{destination_dir}'.")

            folder_count += 1


directory_to_list = "./data"
destination_base_directory = "./data/process_data"

list_files_and_create_directories(
    directory_to_list, destination_base_directory)
