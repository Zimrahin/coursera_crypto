# Answer to question 4 of week 2 quiz
if __name__ == "__main__":
    # Example outputs from 2-round Feistel sequence
    # The outputs are for 0⁶⁴ and 1³²0³²
    outputs: list[tuple] = [
        (0x9F970F4E_932330E4, 0x6068F0B1_B645C008),
        (0x7C2822EB_FDC48BFB, 0x325032A9_C5E2364B),
        (0x4AF53267_1351E2E1, 0x87A40CFA_8DD39154),
        (0x2D1CFA42_C0B1D266, 0xEEA6E3DD_B2146DD0),
    ]

    for left, right in outputs:
        pattern = left ^ right
        print(f"{pattern:#010x}")
