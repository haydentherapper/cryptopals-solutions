# Array to store the state
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff
N = 624
M = 397
mt = [None] * N
index = 0

def init_generator(seed):
	global index,mt

	index = 0
	mt[0] = seed
	for i in range(1, N):
		mt[i] = (0x6c078965 * (mt[i-1] ^ (mt[i-1] >> 30)) + i)
		mt[i] &= 0xffffffff # Lowest 32 bits

def extract_number():
	global index,mt

	if index == 0:
		generate_numbers()

	# Tempering
	y = mt[index]
	y ^= (y >> 11)
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= (y >> 18)

	index = (index + 1) % N
	return y

def generate_numbers():
	global index,mt

	for i in range(N-M):
		y = (mt[i] & UPPER_MASK) | (mt[(i+1) % N] & LOWER_MASK)
		mt[i] = mt[(i+M) % N] ^ (y >> 1) ^ ((y & 1) * 0x9908b0df)
	
	for i in range(N-1):
		y = (mt[i] & UPPER_MASK) | (mt[(i+1) % N] & LOWER_MASK)
		mt[i] = mt[(i + (N-M)) % N] ^ (y >> 1) ^ ((y & 1) * 0x9908b0df)
	
	y = (mt[N-1] & UPPER_MASK) | (mt[0] & LOWER_MASK)
	mt[N-1] = mt[M-1] ^ (y >> 1) ^ ((y & 1) * 0x9908b0df)

	index = 0
