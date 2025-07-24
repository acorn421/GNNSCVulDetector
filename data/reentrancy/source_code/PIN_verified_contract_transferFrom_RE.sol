/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before the allowance deduction. This creates a classic reentrancy scenario where:
 * 
 * 1. **External Call Before State Update**: Added a call to `tokenRecipient(_to).receiveApproval()` before the allowance is decremented
 * 2. **State Persistence**: The `allowance[_from][msg.sender]` remains unchanged until after the external call, allowing the recipient contract to call back into `transferFrom` with the same allowance
 * 3. **Multi-Transaction Exploitation**: 
 *    - Transaction 1: Attacker calls `transferFrom` with malicious contract as `_to`
 *    - During the external call, the malicious contract calls back into `transferFrom` again
 *    - Since allowance hasn't been decremented yet, the second call passes the allowance check
 *    - This can be repeated multiple times within the same transaction, but the vulnerability is stateful because:
 *      - The attacker must first set up allowances in previous transactions
 *      - Multiple calls to `transferFrom` drain the allowance progressively
 *      - The vulnerability depends on the accumulated allowance state from previous approve() calls
 * 
 * 4. **Realistic Implementation**: The external call appears as a legitimate notification mechanism for contract recipients, similar to the existing `approveAndCall` pattern in the contract
 * 
 * The vulnerability requires multiple transactions because:
 * - The attacker must first call `approve()` to set up allowances (Transaction 1)
 * - Then call `transferFrom` to exploit the reentrancy (Transaction 2+)
 * - Each exploitation call depends on the remaining allowance state from previous transactions
 * - The attack becomes more effective with higher accumulated allowances from multiple approve transactions
 */
pragma solidity ^0.4.13;

contract owned {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        owner = newOwner;
    }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

contract PIN is owned {
    /* Public variables of the token */
    string public standard = 'PIN 0.1';
    string public name;
    string public symbol;
    uint8 public decimals = 0;
    uint256 public totalSupply;
    bool public locked;
    uint256 public icoSince;
    uint256 public icoTill;

     /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event IcoFinished();
    event Burn(address indexed from, uint256 value);

    uint256 public buyPrice = 0.01 ether;

    /* Initializes contract with initial supply tokens to the creator of the contract */
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint256 _icoSince,
        uint256 _icoTill,
        uint durationInDays
    ) public {
        totalSupply = initialSupply;

        balanceOf[this] = totalSupply / 100 * 22;             // Give the smart contract 22% of initial tokens
        name = tokenName;                                     // Set the name for display purposes
        symbol = tokenSymbol;                                 // Set the symbol for display purposes

        balanceOf[msg.sender] = totalSupply / 100 * 78;       // Give remaining total supply to contract owner, will be destroyed

        emit Transfer(this, msg.sender, balanceOf[msg.sender]);

        if(_icoSince == 0 && _icoTill == 0) {
            icoSince = now;
            icoTill = now + durationInDays * 35 days;
        }
        else {
            icoSince = _icoSince;
            icoTill = _icoTill;
        }
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(locked == false);                            // Check if smart contract is locked

        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows

        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);              // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;

        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) public returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);

        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(locked == false);                            // Check if smart contract is locked
        require(_value > 0);
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance

        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it's a contract address
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
        
        allowance[_from][msg.sender] -= _value;              // Deduct allowance AFTER external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Transfer(_from, _to, _value);

        return true;
    }

    function buy(uint256 ethers, uint256 time) internal {
        require(locked == false);                            // Check if smart contract is locked
        require(time >= icoSince && time <= icoTill);        // check for ico dates
        require(ethers > 0);                             // check if ethers is greater than zero

        uint amount = ethers / buyPrice;

        require(balanceOf[this] >= amount);                  // check if smart contract has sufficient number of tokens

        balanceOf[msg.sender] += amount;
        balanceOf[this] -= amount;

        emit Transfer(this, msg.sender, amount);
    }

    function () public payable {
        buy(msg.value, now);
    }

    function internalIcoFinished(uint256 time) internal returns (bool) {
        if(time > icoTill) {
            uint256 unsoldTokens = balanceOf[this];

            balanceOf[owner] += unsoldTokens;
            balanceOf[this] = 0;

            emit Transfer(this, owner, unsoldTokens);

            emit IcoFinished();

            return true;
        }

        return false;
    }

    function icoFinished() public onlyOwner {
        internalIcoFinished(now);
    }

    function transferEthers() public onlyOwner {
        owner.transfer(this.balance);
    }

    function setBuyPrice(uint256 _buyPrice) public onlyOwner {
        buyPrice = _buyPrice;
    }

    function setLocked(bool _locked) public onlyOwner {
        locked = _locked;
    }

    function burn(uint256 _value) public onlyOwner returns (bool success) {
        require (balanceOf[msg.sender] > _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }
}