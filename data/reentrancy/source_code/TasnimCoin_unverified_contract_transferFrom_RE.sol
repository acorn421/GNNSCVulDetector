/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
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
 * Injected a stateful, multi-transaction reentrancy vulnerability by adding an external call to the recipient contract after allowance modification but before balance transfer completion. This creates a classic reentrancy window where:
 * 
 * 1. **State Accumulation Phase**: An attacker first sets up allowances across multiple transactions, creating a pool of approved tokens from various addresses.
 * 
 * 2. **Exploitation Phase**: During transferFrom execution, the allowance is decremented first, then an external call is made to the recipient contract. The malicious recipient contract can re-enter transferFrom with different parameters before the original _transfer completes.
 * 
 * 3. **Multi-Transaction Dependency**: The vulnerability exploits the accumulated allowance state from previous transactions. Each transferFrom call modifies the allowance state, but the external call happens before all effects are finalized, allowing reentrant calls to exploit intermediate states.
 * 
 * 4. **Exploitation Mechanics**: 
 *    - Transaction 1-N: Build up allowances via approve() calls
 *    - Transaction N+1: Call transferFrom, which decrements allowance then makes external call
 *    - During external call: Re-enter transferFrom with different _from addresses that have remaining allowances
 *    - The original _transfer hasn't completed, so balance state is in intermediate form
 *    - Multiple transfers can be executed using the same intermediate balance state
 * 
 * The vulnerability requires multiple transactions because:
 * - Prior transactions must establish the allowance state pool
 * - The exploitation depends on accumulated allowances from multiple addresses
 * - Each reentrant call operates on state changes from previous transactions
 * - The attack is not possible in a single transaction due to the need for pre-existing allowance setup
 * 
 * This is a realistic vulnerability pattern where notification hooks are added to token contracts, and the ordering of effects vs. interactions creates the vulnerability window.
 */
pragma solidity >=0.4.22 <0.6.0;

interface tokenRecipient { 
    function receiveApproval(address _from, uint256 _value, address _token, bytes  _extraData) external; 
}

contract TasnimCoin {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 3;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    // This generates a public event on the blockchain that will notify clients
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        totalSupply = 1000000000 * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "TSCoin";                                   // Set the name for display purposes
        symbol = "TS";                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != address(0x0));
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        // Save this for an assertion in the future
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        // Subtract from the sender
        balanceOf[_from] -= _value;
        // Add the same to the recipient
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);
        // Asserts are used to use static analysis to find bugs in your code. They should never fail
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` on behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient contract for notification before transfer completion
        uint size;
        assembly {
            size := extcodesize(_to)
        }
        if (size > 0) {
            (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenReceived(address,address,uint256)", _from, _to, _value));
            // Continue execution regardless of call result
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes memory _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
            return true;
        }
    }

    /**
     * Destroy tokens
     *
     * Remove `_value` tokens from the system irreversibly
     *
     * @param _value the amount of money to burn
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        emit Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
}
