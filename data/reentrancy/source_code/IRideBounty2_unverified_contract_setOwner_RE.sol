/*
 * ===== SmartInject Injection Details =====
 * Function      : setOwner
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 0 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding external calls to both the previous and new owner before and after the state update. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 (Setup)**: Attacker calls setOwner() to set owner to a malicious contract they control. This establishes the malicious contract as the new owner in the state.
 * 
 * **Transaction 2 (Exploitation)**: When any subsequent ownership change occurs, the malicious contract (now stored as the current owner) receives the onOwnershipTransferred() callback. During this callback, the malicious contract can re-enter setOwner() or other functions that depend on the owner state.
 * 
 * **Why Multi-Transaction is Required**:
 * 1. The attacker must first establish their malicious contract as the owner (Transaction 1)
 * 2. The vulnerability can only be triggered when there's a subsequent ownership change that calls back to the now-malicious owner (Transaction 2 or later)
 * 3. The state persistence of the owner variable between transactions is crucial - the malicious contract address must be stored in state from the first transaction to be called in later transactions
 * 
 * **Exploitation Scenario**:
 * - Transaction 1: Attacker sets owner to MaliciousContract
 * - Transaction 2: Creator calls setOwner() to change to legitimate owner
 * - During Transaction 2: MaliciousContract receives onOwnershipTransferred() callback and can re-enter setOwner() or manipulate other functions before the new owner is set
 * - The reentrancy can allow the attacker to maintain control or extract value before losing ownership
 * 
 * This creates a realistic vulnerability where the external calls for ownership notifications enable reentrancy attacks that depend on accumulated state changes across multiple transactions.
 */
pragma solidity ^0.4.16;

interface Token {
    function transferFrom(address _from, address _to, uint256 _value) external;
}

contract IRideBounty2 {
    
    Token public tokenReward;
    address public creator;
    address public owner = 0xBeDF65990326Ed2236C5A17432d9a30dbA3aBFEe;

    uint256 public price;
    uint256 public startDate;
    uint256 public endDate;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    constructor() public {
        creator = msg.sender;
        startDate = 1667260800;
        endDate = 1793491200;
        price = 17500;
        tokenReward = Token(0x69D94dC74dcDcCbadEc877454a40341Ecac34A7c);
    }

    function setOwner(address _owner) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify previous owner about ownership change
        if (owner != address(0)) {
            bool success;
            bytes memory data = abi.encodeWithSignature("onOwnershipTransferred(address)", _owner);
            (success, ) = owner.call(data);
            // Continue regardless of callback success
        }
        
        owner = _owner;
        
        // Notify new owner about receiving ownership
        if (_owner != address(0)) {
            bool success;
            bytes memory data = abi.encodeWithSignature("onOwnershipReceived(address)", msg.sender);
            (success, ) = _owner.call(data);
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }

    function setCreator(address _creator) isCreator public {
        creator = _creator;      
    }

    function setStartDate(uint256 _startDate) isCreator public {
        startDate = _startDate;      
    }

    function setEndtDate(uint256 _endDate) isCreator public {
        endDate = _endDate;      
    }
    
    function setPrice(uint256 _price) isCreator public {
        price = _price;      
    }

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
    	uint amount = msg.value * price;
        tokenReward.transferFrom(owner, msg.sender, amount);
        emit FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}
