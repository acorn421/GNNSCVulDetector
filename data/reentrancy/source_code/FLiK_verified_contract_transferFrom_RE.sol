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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract before state updates. The vulnerability works as follows:
 * 
 * **Changes Made:**
 * 1. Added external call to `tokenRecipient(_to).receiveApproval()` before state updates
 * 2. The call happens after allowance checks but before balance/allowance modifications
 * 3. Uses the existing `tokenRecipient` interface already present in the contract
 * 
 * **Multi-Transaction Exploitation:**
 * 1. **Transaction 1**: Attacker sets up allowance and deploys malicious contract as `_to`
 * 2. **Transaction 2**: Calls `transferFrom` - the external call to malicious contract triggers
 * 3. **Reentrancy**: Malicious contract can call `transferFrom` again with same allowance
 * 4. **State Accumulation**: Multiple calls can drain more tokens than allowance should permit
 * 
 * **Why Multi-Transaction is Required:**
 * - Initial setup requires separate transaction to establish allowance
 * - The malicious contract needs to be deployed and configured beforehand
 * - State changes from first transaction enable subsequent exploitation
 * - The vulnerability leverages persistent allowance state across multiple calls
 * 
 * **Exploitation Flow:**
 * 1. Attacker gets approval for X tokens
 * 2. Calls transferFrom to malicious contract
 * 3. Malicious contract receives receiveApproval callback
 * 4. During callback, calls transferFrom again before original state updates
 * 5. Can extract more tokens than initially approved due to allowance not being decremented yet
 * 
 * This creates a realistic vulnerability where the external call enables reentrancy that can be exploited across multiple transactions, requiring accumulated state changes to be effective.
 */
pragma solidity ^0.4.13;

contract owned {
    address public owner;

    function owned() public {
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

contract FLiK is owned {
    /* Public variables of the token */
    string public standard = 'FLiK 0.1';
    string public name;
    string public symbol;
    uint8 public decimals = 14;
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

    uint256 public buyPrice = 1;

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function FLiK(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol,
        uint256 _icoSince,
        uint256 _icoTill
    ) public {
        totalSupply = initialSupply;
        
        balanceOf[this] = totalSupply / 100 * 90;           // Give the smart contract 90% of initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes

        balanceOf[msg.sender] = totalSupply / 100 * 10;     // Give 10% of total supply to contract owner

        Transfer(this, msg.sender, balanceOf[msg.sender]);

        if(_icoSince == 0 && _icoTill == 0) {
            icoSince = 1503187200;
            icoTill = 1505865600;
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
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(locked == false);                            // Check if smart contract is locked
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====

        // External call to recipient before state updates - enables reentrancy
        uint256 size;
        assembly { size := extcodesize(_to) }
        if (size > 0) {
            tokenRecipient(_to).receiveApproval(_from, _value, this, "");
        }
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====

        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);

        return true;
    }

    function buy(uint256 ethers, uint256 time) internal {
        require(locked == false);                            // Check if smart contract is locked
        require(time >= icoSince && time <= icoTill);        // check for ico dates
        require(ethers > 0);                                 // check if ethers is greater than zero

        uint amount = ethers / buyPrice;

        require(balanceOf[this] >= amount);                  // check if smart contract has sufficient number of tokens

        balanceOf[msg.sender] += amount;
        balanceOf[this] -= amount;

        Transfer(this, msg.sender, amount);
    }

    function () payable public {
        buy(msg.value, now);
    }

    function internalIcoFinished(uint256 time) internal returns (bool) {
        if(time > icoTill) {
            uint256 unsoldTokens = balanceOf[this];

            balanceOf[owner] += unsoldTokens;
            balanceOf[this] = 0;

            Transfer(this, owner, unsoldTokens);

            IcoFinished();

            return true;
        }

        return false;
    }

    /* 0x356e2927 */
    function icoFinished() public onlyOwner {
        internalIcoFinished(now);
    }

    /* 0xd271011d */
    function transferEthers() public onlyOwner {
        owner.transfer(this.balance);
    }

    function setBuyPrice(uint256 _buyPrice) public onlyOwner {
        buyPrice = _buyPrice;
    }

    /*
       locking: 0x211e28b60000000000000000000000000000000000000000000000000000000000000001
       unlocking: 0x211e28b60000000000000000000000000000000000000000000000000000000000000000
    */
    function setLocked(bool _locked) public onlyOwner {
        locked = _locked;
    }
}
