for c in range(0, 6):  # 110 × 5 = 550 < 645
    for b in range(0, 11):  # 60 × 10 = 600 < 645
        remainder = 645 - (110*c + 60*b)
        if remainder % 35 == 0:
            a = remainder // 35
            if a > 0:
                print(a, b, c)