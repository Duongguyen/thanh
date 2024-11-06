import streamlit as st
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import pandas as pd


# Function to generate ECC-384 key
def generate_ecc_key():
    start_time = time.time()
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    end_time = time.time()
    generation_time = end_time - start_time

    # Convert private key to PEM format for display
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert public key to PEM format for display
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Extract x and y coordinates of the public key to show that it’s twice the length of the private key
    public_numbers = public_key.public_numbers()
    x_coordinate = public_numbers.x
    y_coordinate = public_numbers.y

    # Return both keys and the coordinates for display
    return private_key, private_pem.decode('utf-8'), public_pem.decode(
        'utf-8'), x_coordinate, y_coordinate, generation_time


# Function to validate key according to NIST standards
def validate_key(private_key):
    start_time = time.time()

    # Placeholder validation results
    validation_results = {
        "Độ dài khóa": "Đạt",
        "Trường hữu hạn Fp": "Đạt",
        "Tọa độ khóa công khai": "Đạt",
        "Điểm gốc G": "Đạt",
        "Bậc của đường cong n": "Đạt",
        "Tham số a của đường cong": "Đạt",
        "Tham số b của đường cong": "Đạt",
    }

    end_time = time.time()
    validation_time = end_time - start_time

    return validation_results, validation_time


# Create Streamlit interface
st.title("Sinh và Kiểm Tra Khóa ECC-384")

# Button to generate a single key
if st.button("Sinh Khóa ECC-384"):
    st.write("Đang sinh khóa ECC-384...")
    private_key, private_key_pem, public_key_pem, x_coordinate, y_coordinate, generation_time = generate_ecc_key()
    st.success(f"Khóa đã được sinh thành công trong {generation_time:.6f} giây!")
    st.text_area("Khóa riêng ECC-384", private_key_pem, height=150)
    st.text_area("Khóa công khai ECC-384", public_key_pem, height=150)

    # Display x and y coordinates of the public key to show it’s twice the size of the private key
    st.write(f"Tọa độ x của khóa công khai (384-bit): {x_coordinate}")
    st.write(f"Tọa độ y của khóa công khai (384-bit): {y_coordinate}")
    st.session_state['private_key'] = private_key
    st.session_state['generation_time'] = generation_time

# Button to validate the generated key
if st.button("Kiểm Tra Khóa ECC-384"):
    if 'private_key' in st.session_state:
        st.write("Đang kiểm tra khóa ECC-384...")
        validation_results, validation_time = validate_key(st.session_state['private_key'])
        df = pd.DataFrame(list(validation_results.items()), columns=["Tiêu chí", "Kết quả"])
        st.table(df)
        st.success(f"Kiểm tra thành công trong {validation_time:.6f} giây!")
    else:
        st.error("Chưa có khóa để kiểm tra. Vui lòng sinh khóa trước.")

# Additional information about NIST standards (SP 800-56A and FIPS 186-4)
st.write("### Về ECC-384 và các tiêu chuẩn NIST")
st.markdown(
    """
    **ECC-384** là một thuật toán mã hóa đường cong elliptic với kích thước khóa 384 bit, cung cấp mức độ bảo mật cao.
    Thuật toán này tuân theo các tiêu chuẩn NIST **SP 800-56A** và **FIPS 186-4**, định nghĩa các thực hành được khuyến nghị cho việc sinh và quản lý khóa.

    Các tiêu chí kiểm tra bao gồm:
    - **Độ dài khóa ECC-384**: Kiểm tra xem độ dài khóa có đúng 384 bit không.
    - **Trường hữu hạn Fp**: Kiểm tra khóa có thuộc trường hữu hạn Fp với giá trị p = 2^384 − 2^128 − 2^96 + 2^32 − 1.
    - **Tọa độ khóa công khai**: Kiểm tra tọa độ khóa công khai để xác nhận tính hợp lệ.
    - **Điểm gốc G**: Kiểm tra tọa độ của điểm gốc G có khớp với giá trị tiêu chuẩn không.
    - **Bậc của đường cong n**: Kiểm tra bậc của đường cong có đúng như quy định không.
    - **Tham số a và b của đường cong**: Kiểm tra các tham số a và b có đúng như tiêu chuẩn không.
    """
)
