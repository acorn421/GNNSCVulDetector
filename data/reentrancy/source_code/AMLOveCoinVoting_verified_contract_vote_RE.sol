/*
 * ===== SmartInject Injection Details =====
 * Function      : vote
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added External Calls Before State Updates**: Inserted external calls to `token.call()` methods (notifyVote and recordVoteActivity) before the critical state update `yaVoto[msg.sender] = true`. This creates a reentrancy window where the vote restriction can be bypassed.
 * 
 * 2. **Multi-Transaction Exploitation Pattern**: The vulnerability requires multiple transactions to be effective:
 *    - **Transaction 1**: Attacker calls vote(), during external call callback, reenters vote() again before `yaVoto[msg.sender]` is set to true
 *    - **Transaction 2**: Attacker can repeat this pattern, accumulating multiple votes from the same address
 *    - **Transaction 3+**: Continues exploitation to manipulate donation tallies or vote counts
 * 
 * 3. **State Dependency**: The vulnerability depends on persistent state changes across transactions:
 *    - `yaVoto[msg.sender]` remains false during the reentrancy window
 *    - `votosTotales`, `donacionCruzRoja`, `donacionTeleton`, `inclusionEnExchange` are incrementally modified
 *    - Each successful reentrant call increases the attacker's voting power
 * 
 * 4. **Realistic Implementation**: The external calls are realistic for a voting system:
 *    - Token notification mechanisms are common in DeFi protocols
 *    - Vote activity recording could be used for analytics or compliance
 *    - The calls appear legitimate and functional
 * 
 * 5. **Exploitation Mechanism**: 
 *    - Attacker deploys a malicious token contract that implements the callback functions
 *    - During `notifyVote` or `recordVoteActivity`, the malicious contract calls back to `vote()`
 *    - Since `yaVoto[msg.sender]` hasn't been set yet, the check passes
 *    - Attacker can vote multiple times with the same tokens, inflating their voting power
 *    - Each transaction accumulates more voting power, making this a stateful, multi-transaction vulnerability
 * 
 * The vulnerability cannot be exploited in a single transaction because it requires the external contract to be in control during the callback to initiate additional vote() calls.
 */
pragma solidity ^0.4.18;

contract ForeignToken {
    function balanceOf(address _owner) public constant returns (uint256);
}

contract Owned {
    address public owner;
    address public newOwner;

    event OwnershipTransferred(address indexed _from, address indexed _to);

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        newOwner = address(0);
    }
}

contract AMLOveCoinVoting is Owned {
    address private _tokenAddress;
    bool public votingAllowed = false;

    mapping (address => bool) yaVoto;
    uint256 public votosTotales;
    uint256 public donacionCruzRoja;
    uint256 public donacionTeleton;
    uint256 public inclusionEnExchange;

    function AMLOveCoinVoting(address tokenAddress) public {
        _tokenAddress = tokenAddress;
        votingAllowed = true;
    }

    function enableVoting() onlyOwner public {
        votingAllowed = true;
    }

    function disableVoting() onlyOwner public {
        votingAllowed = false;
    }

    function vote(uint option) public {
        require(votingAllowed);
        require(option < 3);
        require(!yaVoto[msg.sender]);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        ForeignToken token = ForeignToken(_tokenAddress);
        uint256 amount = token.balanceOf(msg.sender);
        require(amount > 0);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify token about voting - introduces reentrancy window
        if (token.call(bytes4(keccak256("notifyVote(address,uint256,uint256)")), msg.sender, amount, option)) {
            // Token notification succeeded, proceed with additional external interaction
            token.call(bytes4(keccak256("recordVoteActivity(address,uint256)")), msg.sender, amount);
        }
        
        // State updates happen after external calls - vulnerable to reentrancy
        yaVoto[msg.sender] = true;
        votosTotales += amount;
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        if (option == 0){
            donacionCruzRoja += amount;
        } else if (option == 1) {
            donacionTeleton += amount;
        } else if (option == 2) {
            inclusionEnExchange += amount;
        } else {
            assert(false);
        }        
    }
    
    function getStats() public view returns (
        uint256 _votosTotales,
        uint256 _donacionCruzRoja,
        uint256 _donacionTeleton,
        uint256 _inclusionEnExchange)
    {
        return (votosTotales, donacionCruzRoja, donacionTeleton, inclusionEnExchange);
    }
}