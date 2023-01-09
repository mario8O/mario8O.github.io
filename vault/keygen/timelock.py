import random

system_random = random.SystemRandom()


# strong password config
strong_password_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
strong_password_length = 30

# weak password config that can be cracked within about 1/2 year
weak_password_alphabet = "abcdefghijklmnopqrstuvwxyzZ1234567890"
weak_password_length = 8


# calc time to crack a PBKDF2-based password using 10 parallel GPUs in 2021
def print_time_to_crack_password(alphabet, length):
	million = 1000000
	# https://gist.github.com/epixoip/a83d38f412b4737e99bbef804a270c40
	hashes_per_second = 10 * 23000 * million # 23000 Mio hashes per second raw SHA-256 on 10 GTX 1080 cards
	kdf_iterations = 1 * million
	password_checks_per_second = hashes_per_second / kdf_iterations
	print("password_checks_per_second: " + str(password_checks_per_second))
	
	print("alphabet: " + alphabet)
	alphabet_list = list(alphabet)
	alphabet_length = len(alphabet_list)
	print("alphabet_length: " + str(alphabet_length))
	
	print("length: " + str(length))
	possible_passwords = alphabet_length ** length
	print("possible_passwords: " + str(possible_passwords))

	seconds_to_crack_password = possible_passwords / password_checks_per_second
	print("seconds_to_crack_password: " + str(seconds_to_crack_password))
	hours_to_crack_password = seconds_to_crack_password / 3600
	print("hours_to_crack_password: " + str(hours_to_crack_password))
	days_to_crack_password = hours_to_crack_password / 24
	print("days_to_crack_password: " + str(days_to_crack_password))
	print("###")


def random_password(alphabet, length):
	alphabet_list = list(alphabet)
	password = ""
	for i in range(0, length):
		r = system_random.randrange(0, len(alphabet_list))
		password += alphabet_list[r]
	return password


print_time_to_crack_password(strong_password_alphabet, strong_password_length)
print_time_to_crack_password(weak_password_alphabet, weak_password_length)

for year in range(2021, 2026):
	strong_password = random_password(strong_password_alphabet, strong_password_length)
	weak_password = random_password(weak_password_alphabet, weak_password_length)
	print("timelock puzzle " + str(year) + ": " + strong_password + "-" + weak_password)

# improve passwords strength to compensate increasing GPU performance
weak_password_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
print_time_to_crack_password(weak_password_alphabet, weak_password_length)

for year in range(2026, 2032):
	strong_password = random_password(strong_password_alphabet, strong_password_length)
	weak_password = random_password(weak_password_alphabet, weak_password_length)
	print("timelock puzzle " + str(year) + ": " + strong_password + "-" + weak_password)

