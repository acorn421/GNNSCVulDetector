/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback (`IBurnNotifier(burnNotifier).onBurn()`) after the user's balance is deducted but before totalSupply is updated. This creates a state inconsistency window where:
 * 
 * 1. **Transaction 1**: User calls burn() → balance is reduced → external callback is triggered → malicious contract can re-enter burn() and exploit the inconsistent state where user's balance is already reduced but totalSupply hasn't been updated yet
 * 2. **Transaction 2**: The re-entrant call can potentially burn more tokens than the user actually has, or cause arithmetic underflow/overflow issues
 * 3. **State Persistence**: The balance reduction from the first call persists and affects subsequent re-entrant calls, creating a cumulative vulnerability
 * 
 * The vulnerability is multi-transaction because:
 * - The external callback creates a separate execution context that can trigger new transactions
 * - The state changes (balance reduction) from the initial transaction persist and affect re-entrant calls
 * - The exploit requires the sequence: initial call → callback → re-entrant call → state manipulation
 * - An attacker could potentially drain more tokens than they hold by exploiting this state inconsistency across multiple re-entrant calls
 * 
 * This is realistic because burn notification callbacks are common in DeFi protocols for triggering other contract actions when tokens are burned.
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

interface IBurnNotifier {
    function onBurn(address from, uint256 value) external;
}

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
    address public burnNotifier;
    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function FomoMasterCoin(
    ) public {
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
        Transfer(_from, _to, _value);
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
            Transfer(admin, msg.sender, amount); // Broadcast a message to the blockchain
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
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burn recipient contract before updating totalSupply
        if (burnNotifier != address(0)) {
            IBurnNotifier(burnNotifier).onBurn(msg.sender, _value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
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
        Burn(_from, _value);
        return true;
    }
}
