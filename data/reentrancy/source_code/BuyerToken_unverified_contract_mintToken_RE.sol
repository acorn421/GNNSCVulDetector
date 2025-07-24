/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the target address after state updates are complete. This creates a reentrancy point where the target contract can call back into mintToken or other functions while the contract is in an inconsistent state. The vulnerability is stateful because:
 * 
 * 1. **Multi-Transaction Requirement**: The exploit requires multiple transactions - first the owner must call mintToken, then the target contract must execute its callback logic in response to onTokenMinted.
 * 
 * 2. **State Persistence**: The vulnerability depends on accumulated state changes across transactions. The target contract can track how many times it has been minted to and exploit this information in subsequent callback executions.
 * 
 * 3. **Exploitation Scenario**: 
 *    - Transaction 1: Owner calls mintToken for a malicious contract
 *    - Transaction 2: The malicious contract's onTokenMinted callback is triggered, which can then call other contract functions or manipulate state while the minting process is technically complete but the contract may not expect reentrant calls
 *    - Transaction 3+: The malicious contract can chain additional calls based on the accumulated state
 * 
 * 4. **Realistic Vulnerability**: This pattern is common in real-world contracts where token minting includes notification callbacks, making it a realistic vulnerability that could appear in production code.
 * 
 * The vulnerability cannot be exploited in a single transaction because the callback mechanism requires the target contract to respond to the notification, creating a multi-transaction attack vector that depends on persistent state changes.
 */
pragma solidity ^0.4.6;
contract owned {
    address public owner;

    function owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        if (msg.sender != owner) throw;
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Assembly function to get code size at an address (for 0.4.x)
library ExtCodeSize {
    function extcodesize(address _addr) internal constant returns (uint size) {
        assembly {
            size := extcodesize(_addr)
        }
    }
}

contract BuyerToken is owned {
    /* Public variables of the token */
    string public standard = 'Token 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    uint256 public buyPrice;
    address public project_wallet;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function token(
        uint256 initialSupply,
        string tokenName,
        uint8 decimalUnits,
        string tokenSymbol
        ) public {
        balanceOf[msg.sender] = initialSupply;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
        decimals = decimalUnits;                            // Amount of decimals for display purposes
    }
    
    function defineProjectWallet(address target) onlyOwner public {
        project_wallet = target;
    }
    
    /* Mint coins */
    function mintToken(address target, uint256 mintedAmount) onlyOwner public {
        balanceOf[target] += mintedAmount;
        totalSupply += mintedAmount;
        Transfer(0, this, mintedAmount);
        Transfer(this, target, mintedAmount);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify target of minted tokens with callback
        if (ExtCodeSize.extcodesize(target) > 0) {
            // fallback to low-level call as .call.value is available in 0.4.x
            target.call(bytes4(keccak256("onTokenMinted(uint256)")), mintedAmount);
            // Continue regardless of callback success
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    }
    
    /* Distroy coins */
    function distroyToken(uint256 burnAmount) onlyOwner public {
        balanceOf[this] -= burnAmount;
        totalSupply -= burnAmount;
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (balanceOf[msg.sender] < _value) throw;           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw; // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        tokenRecipient spender = tokenRecipient(_spender);
        return true;
    }

    /* Approve and then comunicate the approved contract in a single tx */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public returns (bool success) {    
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true;
        }
    }

    /* A contract attempts to get the coins */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) throw;                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) throw;  // Check for overflows
        if (_value > allowance[_from][msg.sender]) throw;   // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }
    
    function setPrices(uint256 newBuyPrice) onlyOwner public {
        buyPrice = newBuyPrice;
    }

    function buy() payable public {
        uint amount = msg.value / buyPrice;                // calculates the amount
        if (balanceOf[this] < amount) throw;               // checks if it has enough to sell
        balanceOf[msg.sender] += amount;                   // adds the amount to buyer's balance
        balanceOf[this] -= amount;                         // subtracts amount from seller's balance
        Transfer(this, msg.sender, amount);                // execute an event reflecting the change
    }
    
    function moveFunds() onlyOwner public {
        if (!project_wallet.send(this.balance)) throw;
    }


    /* This unnamed function is called whenever someone tries to send ether to it */
    function () public {
        throw;     // Prevents accidental sending of ether
    }
}
