/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by:
 * 
 * 1. **Added External Call Before State Update**: Introduced an external call to `_to.call()` that attempts to notify the recipient contract about the incoming transfer via `onTokenTransfer()` callback. This creates a reentrancy entry point.
 * 
 * 2. **Moved Critical State Update**: The `allowance[_from][msg.sender] -= _value;` line is now executed AFTER the external call, violating the Checks-Effects-Interactions pattern. This means the allowance remains unchanged during the external call.
 * 
 * 3. **Multi-Transaction Exploitation Pattern**:
 *    - **Transaction 1**: Attacker calls `transferFrom()`, which triggers the external call to a malicious contract
 *    - **During External Call**: The malicious contract can re-enter `transferFrom()` while the allowance is still at its original value
 *    - **Transaction 2**: The re-entrant call can exploit the unchanged allowance state to transfer more tokens than intended
 *    - **State Accumulation**: Each successful re-entry can drain more tokens before the allowance is finally decremented
 * 
 * 4. **Stateful Nature**: The vulnerability relies on the persistent state of the `allowance` mapping between transactions. The attacker can accumulate unauthorized transfers across multiple calls before the allowance is properly updated.
 * 
 * 5. **Realistic Implementation**: The callback mechanism mimics real-world token notification patterns seen in DeFi protocols, making this vulnerability appear legitimate while being exploitable.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract FomoMasterCoin{
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    uint256 public totalEthInWei;  
    uint256 public transferCount;
    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);
   
    address public admin;
    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor() public {
        admin=msg.sender;
        totalSupply = 21000000* 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = "FomoMasterCoin";                                   // Set the name for display purposes
        symbol = "FMMC";                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
        // Check if the sender has enough
        require(balanceOf[_from] >= _value);
        // Check for overflows
        require(balanceOf[_to] + _value > balanceOf[_to]);
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
    
    
        function()  payable public{
       
        uint256 value=msg.value;
        if(value>0 && msg.value>0)
        {
            totalEthInWei = totalEthInWei + msg.value;
            uint256 amount = msg.value * 1000;
            require(balanceOf[admin] >= amount);
    
            balanceOf[admin] = balanceOf[admin]-amount;
            balanceOf[msg.sender] = balanceOf[msg.sender]+amount;
    
            admin.transfer(msg.value);  
            emit Transfer(admin, msg.sender, amount); // Broadcast a message to the blockchain
            transferCount++;
        }   
        
      
    }
    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address
     *
     * Send `_value` tokens to `_to` in behalf of `_from`
     *
     * @param _from The address of the sender
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // External call to recipient for transfer notification - introduces reentrancy point
        if(isContract(_to)) {
            // External call uses low-level call, preserving vulnerability
            // (bool callSuccess,) = _to.call(abi.encodeWithSignature("onTokenTransfer(address,address,uint256)", _from, _to, _value));
            // Since abi.encodeWithSignature is not available in 0.4.16, use bytes4 selector:
            bytes4 sig = bytes4(keccak256("onTokenTransfer(address,address,uint256)"));
            _to.call(sig, _from, _to, _value);
            // Continue regardless of callback success
        }
        
        // State update moved AFTER external call - creates reentrancy vulnerability
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    // Helper function to check if an address is a contract
    function isContract(address _addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    /**
     * Set allowance for other address
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it
     *
     * @param _spender The address authorized to spend
     * @param _value the max amount they can spend
     * @param _extraData some extra information to send to the approved contract
     */
    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
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
