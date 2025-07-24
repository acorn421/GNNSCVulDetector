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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the new owner address before updating the owner state. This creates a CEI (Checks-Effects-Interactions) pattern violation where:
 * 
 * 1. **Multi-Transaction Exploitation Path**:
 *    - Transaction 1: Attacker calls setOwner() with a malicious contract address
 *    - During the external call, the malicious contract can reenter setOwner() or call other functions
 *    - Since owner state hasn't been updated yet, the original creator still has permissions
 *    - The malicious contract can manipulate contract state while having future owner privileges
 * 
 * 2. **State Persistence**: The owner variable persists between transactions, and the vulnerability depends on the timing of when this critical state is updated relative to external calls.
 * 
 * 3. **Realistic Attack Vector**: 
 *    - The malicious contract can call functions like kill() during reentrancy while owner is still the old value
 *    - After the initial call completes, the attacker becomes the new owner
 *    - This creates a scenario where the attacker can exploit both the old and new owner states
 * 
 * 4. **Why Multi-Transaction**: The vulnerability requires the attacker to first deploy a malicious contract, then call setOwner() with that contract address, enabling the reentrancy attack that wouldn't be possible in a single direct transaction.
 */
pragma solidity ^0.4.16;

interface Token {
    function transfer(address _to, uint256 _value) external;
}

contract TBECrowdsale {
    
    Token public tokenReward;
    uint256 public price;
    address public creator;
    address public owner = 0x0;
    uint256 public startDate;
    uint256 public endDate;

    mapping (address => bool) public whitelist;
    mapping (address => bool) public categorie1;
    mapping (address => bool) public categorie2;
    mapping (address => uint256) public balanceOfEther;

    modifier isCreator() {
        require(msg.sender == creator);
        _;
    }

    event FundTransfer(address backer, uint amount, bool isContribution);

    function TBECrowdsale() public {
        creator = msg.sender;
        price = 8000;
        startDate = now;
        endDate = startDate + 30 days;
        tokenReward = Token(0x647972c6A5bD977Db85dC364d18cC05D3Db70378);
    }

    function setOwner(address _owner) isCreator public {
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the new owner before updating state (enables reentrancy)
        if (_owner != address(0)) {
            (bool success, ) = _owner.call(abi.encodeWithSignature("onOwnershipReceived(address,address)", owner, _owner));
            // Don't revert on failure to maintain functionality
        }
        
        // State update happens after external call (CEI violation)
        owner = _owner;
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

    function addToWhitelist(address _address) isCreator public {
        whitelist[_address] = true;
    }

    function addToCategorie1(address _address) isCreator public {
        categorie1[_address] = true;
    }

    function addToCategorie2(address _address) isCreator public {
        categorie2[_address] = true;
    }

    function setToken(address _token) isCreator public {
        tokenReward = Token(_token);      
    }

    function sendToken(address _to, uint256 _value) isCreator public {
        tokenReward.transfer(_to, _value);      
    }

    function kill() isCreator public {
        selfdestruct(owner);
    }

    function () payable public {
        require(msg.value > 0);
        require(now > startDate);
        require(now < endDate);
        require(whitelist[msg.sender]);
        
        if (categorie1[msg.sender]) {
            require(balanceOfEther[msg.sender] <= 2);
        }

        uint256 amount = msg.value * price;

        if (now > startDate && now <= startDate + 5) {
            uint256 _amount = amount / 10;
            amount += _amount * 3;
        }

        balanceOfEther[msg.sender] += msg.value / 1 ether;
        tokenReward.transfer(msg.sender, amount);
        FundTransfer(msg.sender, amount, true);
        owner.transfer(msg.value);
    }
}