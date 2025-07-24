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
 * Total Found   : 4 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the `_from` address before state updates. The vulnerability allows an attacker to:
 * 
 * 1. **Transaction 1**: Deploy a malicious contract and approve it for token burning
 * 2. **Transaction 2**: Call burnFrom() targeting the malicious contract, which triggers the callback before state updates
 * 3. **Callback Exploitation**: The malicious contract can re-enter burnFrom() or manipulate allowances while the original state is still unchanged
 * 4. **State Accumulation**: Multiple transactions can exploit the inconsistent state between checks and updates
 * 
 * The vulnerability is stateful because:
 * - It requires setting up allowances in previous transactions
 * - The malicious contract's state persists between calls
 * - Multiple burn operations can compound the effect
 * - The attacker can manipulate the allowance/balance relationship across transactions
 * 
 * The multi-transaction nature is enforced because:
 * - Initial setup requires separate approve() calls
 * - The callback can initiate additional transactions
 * - State manipulation accumulates across multiple burnFrom() calls
 * - The vulnerability cannot be exploited in a single atomic transaction due to the need for prior allowance setup
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract OysterPrePearl {
    // Public variables of the token
    string public name = "Oyster PrePearl";
    string public symbol = "PREPRL";
    uint8 public decimals = 18;
    uint256 public totalSupply = 0;
    uint256 public funds = 0;
    address public owner;
    bool public saleClosed = false;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    /**
     * Constructor function
     *
     * Initializes contract
     */
    constructor() public {
        owner = msg.sender;
    }
    
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    
    function closeSale() onlyOwner public {
        saleClosed = true;
    }

    function openSale() onlyOwner public {
        saleClosed = false;
    }
    
    function () payable public {
        require(!saleClosed);
        require(msg.value >= 10 finney);
        require(funds + msg.value <= 480 finney);
        uint buyPrice;
        if (msg.value >= 200 finney) {
            buyPrice = 32500;//650%
        }
        else if (msg.value >= 100 finney) {
            buyPrice = 17500;//350%
        }
        else if (msg.value >= 50 finney) {
            buyPrice = 12500;//250%
        }
        else buyPrice = 10000;//100%
        uint amount;
        amount = msg.value * buyPrice;                    // calculates the amount
        totalSupply += amount;                            // increases the total supply 
        balanceOf[msg.sender] += amount;                  // adds the amount to buyer's balance
        funds += msg.value;                               // track eth amount raised
        emit Transfer(this, msg.sender, amount);               // execute an event reflecting the change
    }
    
    function withdrawFunds() onlyOwner public {
        owner.transfer(address(this).balance);
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
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify burn recipient with callback before state updates (VULNERABILITY)
        if (extcodesize(_from) > 0) {
            // low-level call to keep Solidity 0.4.16 compatibility
            _from.call(abi.encodeWithSignature("onBurnNotification(address,uint256)", msg.sender, _value));
            // Continue regardless of callback success
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
    
    // Helper for extcodesize in old Solidity versions
    function extcodesize(address _addr) internal view returns (uint256 size) {
        assembly { size := extcodesize(_addr) }
    }
}
