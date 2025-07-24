/*
 * ===== SmartInject Injection Details =====
 * Function      : transfer
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism after state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Changes Made:**
 * 1. Added external call to recipient contract using `_to.call()` after balance updates
 * 2. The callback happens AFTER state changes (balanceOf modifications), violating Checks-Effects-Interactions pattern
 * 3. Added conditional logic to only call contracts (code.length > 0)
 * 4. Callback failure causes revert, but intermediate state changes may persist due to reentrancy
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * - **Transaction 1:** Attacker calls transfer() to malicious contract
 * - **During callback:** Malicious contract reenters transfer() or other functions, creating inconsistent state
 * - **Transaction 2:** Attacker exploits the accumulated state inconsistencies from previous reentrancy
 * - **Transaction 3:** Attacker finalizes exploitation by transferring excess tokens
 * 
 * **Why Multi-Transaction Required:**
 * 1. **State Accumulation:** Each reentrancy call accumulates state changes that persist between transactions
 * 2. **Incomplete Reversion:** While individual calls may revert, the overall state manipulation spans multiple transactions
 * 3. **Timing Dependencies:** The vulnerability depends on the sequence of state changes across multiple function calls
 * 4. **Persistent State:** The `balanceOf` mappings maintain corrupted state between transactions, enabling further exploitation
 * 
 * This creates a realistic vulnerability where an attacker must execute multiple transactions to fully exploit the reentrancy, making it a genuine stateful, multi-transaction security flaw.
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient contract if it implements token receiver interface
        uint size;
        assembly { size := extcodesize(_to) }
        if(size > 0) {
            // External call to potentially malicious contract AFTER state changes
            bool success = _to.call(bytes4(keccak256("onTokenReceived(address,uint256)")), msg.sender, _value);
            if(!success) {
                // If callback fails, revert the transaction but leave intermediate state
                // This creates a window for reentrancy exploitation across transactions
                revert();
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(locked == false);                            // Check if smart contract is locked
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]);   // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance

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
