from hashlib import md5

m1 = "TEXTCOLLBYfGiJUETHQ4hAcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"
m2 = "TEXTCOLLBYfGiJUETHQ4hEcKSMd5zYpgqf1YRDhkmxHkhPWptrkoyz28wnI9V0aHeAuaKnak"


# #m1 = """
# "aWhXJ<f}is%/M#qvS";p>()#tt(<)Oni)co?|_Pa)-{atRkzm]=z)!Xrwb0R/0vhx+~?(70SYB+IemMAhHpW9j$m*f q)Q}:TW,zg{*SfSsumAR,@SX  $ )   u?!s
# """.strip().encode()
# m2 = """
# "aWhXJ<f}is%/M#qvS";pB()#tt(<)Oni)co?|_Pa)-{atRkzm]=z)!Xrwb0R/0vhx+~?(70SYB+IemMAhHpW9j$m*f q)Q}:TW,zg{*SfSsumAR,@SX  $ )   u?!s
# """.strip().encode()


# h1 = md5(m1).hexdigest()
# h2 = md5(m2).hexdigest()
# print(f"{h1=}, {h2=}")


# suffix = b"12357"
# h1 = md5(m1 + suffix).hexdigest()
# h2 = md5(m2 + suffix).hexdigest()
# print(f"{h1=}, {h2=}")
# print(m1)


def calc_game_state_hash(game_state):
    import hashlib

    f = game_state["player_name"].strip()
    e = game_state["apple_size"]
    s = f"{f}_{e}".encode("utf-8")

    return hashlib.md5(s).hexdigest()


g1 = {"player_name": m1, "apple_size": "1"}
g2 = {"player_name": m1, "apple_size": "10000"}

print(calc_game_state_hash(g1))
print(calc_game_state_hash(g2))
