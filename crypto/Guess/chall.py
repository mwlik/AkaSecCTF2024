import random

FLAG = 'AKASEC{fake_flag}'

state = random.randint(0, 15)

def LFSR():
    global state
    while True:
        yield state % 3
        bit = (state ^ (state >> 1) ^ (state >> 3) ^ (state >> 4)) & 1
        state = (state >> 1) | (bit << 3)

rng = LFSR()

number_of_games = 20

actions = {0: 'Rock', 1: 'Paper', 2: 'Scissors'}
reverse_actions = {'Rock': 0, 'Paper': 1, 'Scissors': 2}

machine_choices = [next(rng) for _ in range(number_of_games)]
while sum(machine_choices)/len(machine_choices) != 1:
    state = random.randint(0, 15)
    machine_choices = [next(rng) for _ in range(number_of_games)]


player_guesses = []

print("You have six free inspections: ")
for i in range(6):
    machine_choice = machine_choices[i]
    print("Machine's choice:", actions[machine_choice])
    player_guesses.append(machine_choice)

print("\nActual guessing begins.")
for i in range(6, number_of_games):
    guess = input("Enter your guess (Rock, Paper, Scissors): ")
    player_guesses.append(reverse_actions[guess])

def check_guesses(player_guesses, machine_choices):
    for i in range(number_of_games):
        if player_guesses[i] != machine_choices[i]:
            return False
    return True

if check_guesses(player_guesses, machine_choices):
    print(f"Congratulations! You guessed all choices correctly, FLAG: {FLAG}")
else:
    print("You couldn't guess all choices correctly.")