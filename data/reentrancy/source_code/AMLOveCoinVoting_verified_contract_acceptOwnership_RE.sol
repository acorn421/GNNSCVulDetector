/*
 * ===== SmartInject Injection Details =====
 * Function      : acceptOwnership
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the previous owner before completing state updates. This creates a window where the contract is in an inconsistent state (newOwner is set but owner hasn't been updated yet), allowing for complex multi-transaction exploits.
 * 
 * **Specific Changes Made:**
 * 1. Added an external call to the previous owner using `owner.call()` after the event emission but before state updates
 * 2. The call attempts to notify the previous owner about the ownership transfer
 * 3. State updates (owner assignment and newOwner reset) occur after the external call, violating the Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * Transaction 1: Attacker calls `transferOwnership(attackerContract)` where attackerContract is a malicious contract
 * Transaction 2: Attacker calls `acceptOwnership()` from attackerContract:
 *    - The require check passes (msg.sender == newOwner)
 *    - Event is emitted
 *    - External call is made to the previous owner (if it's a contract)
 *    - If the previous owner is also controlled by the attacker, it can reenter
 *    - During reentrancy, the contract state shows: owner = oldOwner, newOwner = attackerContract
 *    - The attacker can exploit this inconsistent state by calling other functions that depend on ownership
 * Transaction 3: After reentrancy completes, the state is finally updated, but damage may already be done
 * 
 * **Why Multi-Transaction Exploitation:**
 * - Transaction 1 is required to set up the ownership transfer (calling transferOwnership)
 * - Transaction 2 triggers the vulnerability during acceptOwnership execution
 * - The vulnerability exploits the persistent state between newOwner being set (in Transaction 1) and owner being updated (in Transaction 2)
 * - Additional transactions may be needed to fully exploit the inconsistent state during the reentrancy window
 * - The attack requires coordination across multiple transactions to manipulate the ownership state effectively
 * 
 * This creates a realistic scenario where an attacker needs to plan a multi-step attack, accumulating state changes across transactions to exploit the reentrancy vulnerability.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to notify previous owner before state updates
        if (owner != address(0)) {
            bool success = owner.call(abi.encodeWithSignature("onOwnershipTransferred(address,address)", owner, newOwner));
            // Continue regardless of success to maintain backward compatibility
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
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
        yaVoto[msg.sender] = true;
        ForeignToken token = ForeignToken(_tokenAddress);
        uint256 amount = token.balanceOf(msg.sender);
        require(amount > 0);
        votosTotales += amount;
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