"""
Advanced Electronic Voting Machine System
A secure and transparent digital voting system with multiple security layers.
"""

__version__ = "1.0.0"
__author__ = "EVM System"

from .auth import Authentication
from .voter import VoterManager
from .candidate import CandidateManager
from .election import ElectionManager
from .voting import VotingMachine
from .results import ResultManager
from .security import SecurityManager
from .database import DatabaseManager

__all__ = [
    'Authentication',
    'VoterManager',
    'CandidateManager',
    'ElectionManager',
    'VotingMachine',
    'ResultManager',
    'SecurityManager',
    'DatabaseManager'
]