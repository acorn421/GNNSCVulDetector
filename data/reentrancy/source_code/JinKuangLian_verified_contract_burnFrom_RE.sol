/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to IBurnNotification(_from).onBurn() before state updates. This creates a realistic burn notification mechanism that allows the _from address (if it's a contract) to react to burn operations. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1 Setup**: Attacker deploys malicious contract and gets approval for burning tokens
 * **Transaction 2 Exploitation**: When burnFrom is called, the malicious contract's onBurn callback can:
 * - Call approve() to increase allowance for itself or accomplices
 * - Call transfer() to move tokens before they're burned
 * - Manipulate other contract state that affects subsequent burn operations
 * 
 * The key insight is that the allowance state persists between transactions, and the external call happens before the allowance reduction, enabling multi-transaction exploitation patterns where attackers can manipulate allowances during the callback and exploit them in subsequent transactions.
 * 
 * **Multi-Transaction Attack Vector**:
 * 1. **Setup Phase** (Transaction 1): Attacker gets initial allowance approval
 * 2. **Exploitation Phase** (Transaction 2): During burnFrom call, onBurn callback manipulates allowance/balance state
 * 3. **Abuse Phase** (Transaction 3+): Subsequent calls exploit the manipulated state
 * 
 * The vulnerability is stateful because it relies on the allowance mechanism and balance state that persists between transactions, making it impossible to exploit in a single atomic transaction.
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

// Interface for reentrancy notification
interface IBurnNotification {
    function onBurn(address sender, uint256 value) external;
}

contract JinKuangLian{
    string public standard = 'JinKuangLian 0.1';
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;

    /* This creates an array with all balances */
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    /* This generates a public event on the blockchain that will notify clients */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /* This notifies clients about the amount burnt */
    event Burn(address indexed from, uint256 value);

    /* Initializes contract with initial supply tokens to the creator of the contract */
    function JinKuangLian() public {
        balanceOf[msg.sender] =  1200000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  1200000000 * 1000000000000000000;                        // Update total supply
        name = "JinKuangLian";                                   // Set the name for display purposes
        symbol = "JKL";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        require(_to != 0x0);                               // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[msg.sender] >= _value);           // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
    }

    /* Allow another contract to spend some tokens in your behalf */
    function approve(address _spender, uint256 _value)
        public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /* Approve and then communicate the approved contract in a single tx */
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
        require(_to != 0x0);                                // Prevent transfer to 0x0 address. Use burn() instead
        require(balanceOf[_from] >= _value);                 // Check if the sender has enough
        require(balanceOf[_to] + _value >= balanceOf[_to]);  // Check for overflows
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify the token holder about the burn operation before state updates
        if (isContract(_from)) {
            IBurnNotification(_from).onBurn(msg.sender, _value);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        allowance[_from][msg.sender] -= _value;              // Reduce allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true;
    }
    /* Helper to check if an address is a contract */
    function isContract(address _addr) internal constant returns (bool)
    {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}