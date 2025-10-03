import random
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Card:
    """Represents a single playing card with suit and rank."""
    suit: str
    rank: str
    
    def __str__(self):
        return f"{self.rank} of {self.suit}"
    
    @property
    def value(self) -> int:
        """Returns the numerical value of the card."""
        if self.rank in ['Jack', 'Queen', 'King']:
            return 10
        elif self.rank == 'Ace':
            return 11  # Soft value, will be adjusted in Hand
        else:
            return int(self.rank)

class Deck:
    """Represents a deck of cards with advanced features."""
    
    def __init__(self, num_decks: int = 6):
        self.cards: List[Card] = []
        self.num_decks = num_decks
        self.build()
        self.shuffle()
        self.cut_card_position = int(len(self.cards) * 0.7)  # Place cut card at 70%
    
    def build(self):
        """Builds multiple fresh decks of cards."""
        suits = ['Hearts', 'Diamonds', 'Clubs', 'Spades']
        ranks = ['2', '3', '4', '5', '6', '7', '8', '9', '10', 'Jack', 'Queen', 'King', 'Ace']
        
        self.cards = [
            Card(suit, rank)
            for _ in range(self.num_decks)
            for suit in suits
            for rank in ranks
        ]
    
    def shuffle(self):
        """Shuffles the deck using Fisher-Yates algorithm."""
        for i in range(len(self.cards)-1, 0, -1):
            j = random.randint(0, i)
            self.cards[i], self.cards[j] = self.cards[j], self.cards[i]
    
    def deal(self) -> Card:
        """Deals one card from the deck and checks for reshuffle."""
        if len(self.cards) < self.cut_card_position:
            print("\nCut card reached! Reshuffling deck...")
            self.build()
            self.shuffle()
            self.cut_card_position = int(len(self.cards) * 0.7)
        
        return self.cards.pop()
    
    def __len__(self) -> int:
        return len(self.cards)

class Hand:
    """Represents a hand of cards with advanced features."""
    
    def __init__(self):
        self.cards: List[Card] = []
        self.value: int = 0
        self.aces: int = 0
    
    def add_card(self, card: Card):
        """Adds a card to the hand and adjusts value."""
        self.cards.append(card)
        self.value += card.value
        if card.rank == 'Ace':
            self.aces += 1
        self._adjust_for_ace()
    
    def _adjust_for_ace(self):
        """Adjusts the value of aces from 11 to 1 if needed."""
        while self.value > 21 and self.aces:
            self.value -= 10
            self.aces -= 1
    
    def is_blackjack(self) -> bool:
        """Check if hand is a blackjack (Ace + 10-value card)."""
        return len(self.cards) == 2 and self.value == 21
    
    def is_busted(self) -> bool:
        """Check if hand value exceeds 21."""
        return self.value > 21
    
    def can_split(self) -> bool:
        """Check if hand can be split (two cards of same rank)."""
        return len(self.cards) == 2 and self.cards[0].rank == self.cards[1].rank
    
    def __str__(self) -> str:
        return ', '.join(str(card) for card in self.cards)

class PlayerBase(ABC):
    """Abstract base class for players."""
    
    def __init__(self, name: str):
        self.name = name
        self.hands: List[Hand] = [Hand()]
        self.current_hand_index = 0
    
    @property
    def current_hand(self) -> Hand:
        return self.hands[self.current_hand_index]
    
    @abstractmethod
    def make_decision(self, dealer_up_card: Card) -> str:
        """Determine the player's action."""
        pass
    
    def reset_hands(self):
        """Reset hands for new round."""
        self.hands = [Hand()]
        self.current_hand_index = 0

class HumanPlayer(PlayerBase):
    """Human player with betting capabilities."""
    
    def __init__(self, name: str, initial_chips: int = 1000):
        super().__init__(name)
        self.chips = initial_chips
        self.bet_amount = 0
        self.insurance_bet = 0
    
    def place_bet(self, amount: int) -> bool:
        """Place a bet for the round."""
        if amount > self.chips:
            print("Not enough chips!")
            return False
        self.bet_amount = amount
        self.chips -= amount
        return True
    
    def place_insurance(self, amount: int) -> bool:
        """Place an insurance bet."""
        if amount > self.chips:
            print("Not enough chips for insurance!")
            return False
        self.insurance_bet = amount
        self.chips -= amount
        return True
    
    def win_bet(self, amount: int, blackjack: bool = False):
        """Add winnings to chips."""
        payout = amount * (2.5 if blackjack else 2)
        self.chips += int(payout)
    
    def win_insurance(self):
        """Pay out insurance bet."""
        self.chips += self.insurance_bet * 3  # 2:1 payout
    
    def make_decision(self, dealer_up_card: Card) -> str:
        """Get player decision through input."""
        options = ["(H)it", "(S)tand"]
        
        if len(self.current_hand.cards) == 2:
            if self.current_hand.can_split() and len(self.hands) < 4:
                options.append("(P)plit")
            options.append("(D)ouble down")
        
        print("\nOptions:", " ".join(options))
        
        while True:
            choice = input("Your move: ").lower()
            if choice in ['h', 'hit']:
                return 'hit'
            elif choice in ['s', 'stand']:
                return 'stand'
            elif choice in ['d', 'double'] and '(D)ouble down' in ' '.join(options):
                return 'double'
            elif choice in ['p', 'split'] and '(P)plit' in ' '.join(options):
                return 'split'
            print("Invalid choice. Please try again.")

class Dealer(PlayerBase):
    """Dealer with specific rules."""
    
    def __init__(self):
        super().__init__("Dealer")
        self.up_card: Optional[Card] = None
    
    def make_decision(self, dealer_up_card: Card = None) -> str:
        """Dealer always hits on 16 or less, stands on 17+."""
        return 'hit' if self.current_hand.value < 17 else 'stand'
    
    def show_up_card(self) -> str:
        """Show the dealer's up card."""
        return str(self.up_card) if self.up_card else "No card showing"
    
    def reset_hands(self):
        """Reset hands and clear up card."""
        super().reset_hands()
        self.up_card = None

class BlackjackGame:
    """Manages the game flow with advanced rules."""
    
    def __init__(self):
        self.deck = Deck(num_decks=6)
        self.player = HumanPlayer("Player", initial_chips=1000)
        self.dealer = Dealer()
        self.round_number = 0
    
    def clear_screen(self):
        """Clear the console screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_table(self, show_all_dealer_cards: bool = False):
        """Display the current game state."""
        self.clear_screen()
        print(f"Round {self.round_number} | Chips: {self.player.chips} | Bet: {self.player.bet_amount}")
        print("\nDealer's Hand:")
        
        if show_all_dealer_cards:
            print(f"{self.dealer.current_hand} (Total: {self.dealer.current_hand.value})")
        else:
            print(f"{self.dealer.show_up_card()}, [Hidden]")
        
        print("\nYour Hands:")
        for i, hand in enumerate(self.player.hands):
            status = " (Current)" if i == self.player.current_hand_index else ""
            print(f"Hand {i+1}: {hand} (Total: {hand.value}){status}")
    
    def deal_initial_cards(self):
        """Deal the initial two cards to each participant."""
        for _ in range(2):
            self.player.current_hand.add_card(self.deck.deal())
            dealer_card = self.deck.deal()
            self.dealer.current_hand.add_card(dealer_card)
            if len(self.dealer.current_hand.cards) == 1:
                self.dealer.up_card = dealer_card
    
    def offer_insurance(self):
        """Offer insurance if dealer shows an Ace."""
        if self.dealer.up_card.rank == 'Ace':
            self.show_table()
            print("\nDealer shows an Ace. Insurance?")
            print(f"1. Yes (Up to {self.player.bet_amount // 2})")
            print("2. No")
            
            choice = input("Choose: ")
            if choice == '1':
                while True:
                    try:
                        amount = int(input(f"Insurance amount (1-{self.player.bet_amount // 2}): "))
                        if 1 <= amount <= self.player.bet_amount // 2:
                            self.player.place_insurance(amount)
                            break
                    except ValueError:
                        print("Invalid amount.")
    
    def check_insurance(self):
        """Check if insurance bet wins."""
        if self.dealer.current_hand.is_blackjack() and self.player.insurance_bet > 0:
            print("\nDealer has blackjack! Insurance pays 2:1")
            self.player.win_insurance()
    
    def handle_blackjack(self):
        """Check for immediate blackjack outcomes."""
        player_blackjack = any(hand.is_blackjack() for hand in self.player.hands)
        dealer_blackjack = self.dealer.current_hand.is_blackjack()
        
        if player_blackjack or dealer_blackjack:
            self.show_table(show_all_dealer_cards=True)
            
            if player_blackjack and dealer_blackjack:
                print("\nBoth have blackjack! Push.")
                for hand in self.player.hands:
                    if hand.is_blackjack():
                        self.player.chips += self.player.bet_amount
            elif player_blackjack:
                print("\nBlackjack! You win 3:2!")
                for hand in self.player.hands:
                    if hand.is_blackjack():
                        self.player.win_bet(self.player.bet_amount, blackjack=True)
            elif dealer_blackjack:
                print("\nDealer has blackjack! You lose.")
            
            input("\nPress Enter to continue...")
            return True
        return False
    
    def player_turn(self):
        """Handle all player hands and decisions."""
        for i in range(len(self.player.hands)):
            self.player.current_hand_index = i
            self.handle_single_hand()
    
    def handle_single_hand(self):
        """Process a single hand for the player."""
        while True:
            self.show_table()
            
            if self.player.current_hand.is_busted():
                print("\nBust! You went over 21.")
                break
            
            decision = self.player.make_decision(self.dealer.up_card)
            
            if decision == 'hit':
                self.player.current_hand.add_card(self.deck.deal())
            elif decision == 'stand':
                break
            elif decision == 'double':
                if self.player.place_bet(self.player.bet_amount):
                    self.player.current_hand.add_card(self.deck.deal())
                    break
            elif decision == 'split':
                self.split_hand()
    
    def split_hand(self):
        """Split the current hand into two hands."""
        if len(self.player.hands) >= 4:
            print("Maximum splits (3) reached.")
            return
        
        original_hand = self.player.current_hand
        new_hand = Hand()
        
        # Move second card to new hand
        new_hand.add_card(original_hand.cards.pop())
        original_hand.value -= new_hand.cards[0].value
        if new_hand.cards[0].rank == 'Ace':
            original_hand.aces -= 1
        
        # Add new hand and place additional bet
        self.player.hands.append(new_hand)
        self.player.place_bet(self.player.bet_amount)
        
        # Deal new cards to both hands
        original_hand.add_card(self.deck.deal())
        new_hand.add_card(self.deck.deal())
    
    def dealer_turn(self):
        """Handle the dealer's turn."""
        if any(not hand.is_busted() for hand in self.player.hands):
            self.show_table(show_all_dealer_cards=True)
            
            while self.dealer.make_decision() == 'hit':
                print("\nDealer hits...")
                self.dealer.current_hand.add_card(self.deck.deal())
                self.show_table(show_all_dealer_cards=True)
                
                if self.dealer.current_hand.is_busted():
                    print("\nDealer busts!")
                    break
    
    def determine_winners(self):
        """Determine the outcome for each player hand."""
        dealer_value = self.dealer.current_hand.value
        dealer_busted = self.dealer.current_hand.is_busted()
        
        for i, hand in enumerate(self.player.hands):
            if hand.is_busted():
                print(f"\nHand {i+1}: Bust - You lose.")
                continue
            
            if dealer_busted:
                print(f"\nHand {i+1}: Dealer busts - You win!")
                self.player.win_bet(self.player.bet_amount)
            elif hand.value > dealer_value:
                print(f"\nHand {i+1}: You win! ({hand.value} vs {dealer_value})")
                self.player.win_bet(self.player.bet_amount)
            elif hand.value < dealer_value:
                print(f"\nHand {i+1}: You lose. ({hand.value} vs {dealer_value})")
            else:
                print(f"\nHand {i+1}: Push. ({hand.value} vs {dealer_value})")
                self.player.chips += self.player.bet_amount
    
    def play_round(self):
        """Play a single round of blackjack."""
        self.round_number += 1
        self.player.reset_hands()
        self.dealer.reset_hands()
        
        # Place bet
        self.show_table()
        while True:
            try:
                bet = int(input("\nPlace your bet (1-{}): ".format(self.player.chips)))
                if 1 <= bet <= self.player.chips and self.player.place_bet(bet):
                    break
            except ValueError:
                print("Invalid bet amount.")
        
        # Deal initial cards
        self.deal_initial_cards()
        
        # Check for immediate blackjack
        if self.handle_blackjack():
            return
        
        # Offer insurance
        self.offer_insurance()
        self.check_insurance()
        
        # Player's turn
        self.player_turn()
        
        # Dealer's turn
        self.dealer_turn()
        
        # Determine winners
        self.determine_winners()
        
        input("\nPress Enter to continue...")
    
    def play_game(self):
        """Main game loop."""
        while True:
            self.clear_screen()
            
            if self.player.chips <= 0:
                print("You're out of chips! Game over.")
                break
            
            print(f"Advanced Blackjack | Chips: {self.player.chips}")
            print("\n1. Play a hand")
            print("2. View rules")
            print("3. Quit")
            
            choice = input("\nEnter your choice: ")
            
            if choice == '1':
                self.play_round()
            elif choice == '2':
                self.show_rules()
            elif choice == '3':
                print(f"\nThanks for playing! Final chips: {self.player.chips}")
                break
            else:
                print("Invalid choice. Please try again.")
    
    def show_rules(self):
        """Display the game rules."""
        self.clear_screen()
        print("""
        Advanced Blackjack Rules:
        
        - 6-deck shoe, reshuffled` when 70% of cards are used
        - Dealer stands on all 17s
        - Blackjack pays 3:2
        - Insurance pays 2:1 (when dealer shows Ace)
        - Split up to 3 times (4 hands total)
        - Double down on any two cards
        - Late surrender not available
        
        Special Moves:
        - Hit (H): Take another card
        - Stand (S): Keep your current hand
        - Double (D): Double your bet and take one more card
        - Split (P): Split matching cards into two hands
        """)
        input("\nPress Enter to return to menu...")

if __name__ == "__main__":
    game = BlackjackGame()
    game.play_game()