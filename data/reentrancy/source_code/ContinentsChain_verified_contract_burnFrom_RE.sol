/*
 * ===== SmartInject Injection Details =====
 * Function      : burnFrom
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
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding External Call**: Inserted a callback to the token holder (_from) after state modifications but before allowance update
 * 2. **Violating CEI Pattern**: The external call occurs after critical state changes (balanceOf, totalSupply) but before the allowance update
 * 3. **Creating State Inconsistency Window**: During the callback, the contract has inconsistent state - tokens are burned but allowance isn't updated yet
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker deploys a malicious contract that implements onTokenBurn
 * - Attacker approves the malicious contract to spend tokens
 * - Sets up initial state for exploitation
 * 
 * **Transaction 2 (Primary Attack):**
 * - Victim calls burnFrom on attacker's malicious contract
 * - During the onTokenBurn callback, the malicious contract has a window where:
 *   - balanceOf[attacker] is reduced
 *   - totalSupply is reduced  
 *   - BUT allowance[attacker][victim] is NOT yet decreased
 * - The malicious contract can call other functions (transfer, approve, etc.) exploiting this inconsistent state
 * - Can potentially call burnFrom again with the same allowance before it's decremented
 * 
 * **Transaction 3+ (Exploitation):**
 * - Attacker can exploit the accumulated state changes from previous reentrancy
 * - Can manipulate allowances set during reentrancy windows
 * - Can drain tokens by repeatedly exploiting the allowance inconsistency
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires setting up malicious contracts with specific callback implementations
 * - The attacker needs to accumulate allowances and manipulate state across multiple calls
 * - Each reentrancy window creates small inconsistencies that compound over multiple transactions
 * - The exploit relies on state persistence between transactions to be effective
 */
pragma solidity ^0.4.8;
contract tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData); }

contract ContinentsChain   {
    string public standard = 'ContinentsChain 0.1';
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
    constructor() public {
        balanceOf[msg.sender] =  93000000 * 1000000000000000000;              // Give the creator all initial tokens
        totalSupply =  93000000 * 1000000000000000000;                        // Update total supply
        name = "ContinentsChain";                                   // Set the name for display purposes
        symbol = "CIT";                               // Set the symbol for display purposes
        decimals = 18;                            // Amount of decimals for display purposes
    }

    /* Send coins */
    function transfer(address _to, uint256 _value) public {
        if (_to == 0x0) revert();                               // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[msg.sender] < _value) revert();           // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert(); // Check for overflows
        balanceOf[msg.sender] -= _value;                     // Subtract from the sender
        balanceOf[_to] += _value;                            // Add the same to the recipient
        emit Transfer(msg.sender, _to, _value);                   // Notify anyone listening that this transfer took place
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
        if (_to == 0x0) revert();                                // Prevent transfer to 0x0 address. Use burn() instead
        if (balanceOf[_from] < _value) revert();                 // Check if the sender has enough
        if (balanceOf[_to] + _value < balanceOf[_to]) revert();  // Check for overflows
        if (_value > allowance[_from][msg.sender]) revert();     // Check allowance
        balanceOf[_from] -= _value;                           // Subtract from the sender
        balanceOf[_to] += _value;                             // Add the same to the recipient
        allowance[_from][msg.sender] -= _value;
        emit Transfer(_from, _to, _value);
        return true;
    }

    function burn(uint256 _value) public returns (bool success) {
        if (balanceOf[msg.sender] < _value) revert();            // Check if the sender has enough
        balanceOf[msg.sender] -= _value;                      // Subtract from the sender
        totalSupply -= _value;                                // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        if (balanceOf[_from] < _value) revert();                // Check if the sender has enough
        if (_value > allowance[_from][msg.sender]) revert();    // Check allowance
        balanceOf[_from] -= _value;                          // Subtract from the sender
        totalSupply -= _value;                               // Updates totalSupply
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token holder about the burn via callback
        if (isContract(_from)) {
            /* solhint-disable-next-line avoid-call-value */
            _from.call(bytes4(keccak256("onTokenBurn(address,uint256)")), msg.sender, _value);
            // Continue execution regardless of callback success
        }
        
        allowance[_from][msg.sender] -= _value;              // Decrease allowance after external call
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        emit Burn(_from, _value);
        return true;
    }

    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return (length > 0);
    }
}
