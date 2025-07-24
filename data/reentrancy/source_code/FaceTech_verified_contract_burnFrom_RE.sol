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
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by adding an external call to the `_from` address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Transaction 1: Setup Phase**
 * - Attacker deploys a malicious contract that implements `onBeforeBurn` callback
 * - Attacker calls `approve()` to grant allowance to their externally owned account (EOA)
 * - The malicious contract now has tokens and an approved spender
 * 
 * **Transaction 2: Initial Exploit**
 * - Attacker calls `burnFrom()` with their malicious contract as `_from`
 * - The function performs checks, then calls the malicious contract's `onBeforeBurn` callback
 * - Inside the callback, the malicious contract re-enters `burnFrom()` again before the original call completes state updates
 * 
 * **Multi-Transaction Exploitation Process:**
 * 1. **State Dependency**: The vulnerability depends on the persistent allowance state set in previous transactions
 * 2. **Accumulated Effect**: Each reentrant call can burn tokens based on the same allowance, effectively burning more tokens than the allowance should permit
 * 3. **Cross-Transaction State**: The allowance isn't updated until after the external call, so multiple reentrant calls can exploit the same allowance value
 * 
 * **Why Multiple Transactions are Required:**
 * - The allowance must be set up in a prior transaction using `approve()`
 * - The exploit requires the malicious contract to be deployed and configured beforehand
 * - The reentrancy attack leverages the persistent state (allowance) that was established in earlier transactions
 * - Single transaction exploitation is not possible because the allowance setup and burn exploitation must be separate operations
 * 
 * The vulnerability violates the Checks-Effects-Interactions pattern by making an external call before updating critical state variables (`balanceOf`, `allowance`, `totalSupply`).
 */
pragma solidity ^0.4.13;
contract owned {
    address public owner;
    mapping (address =>  bool) public admins;

    function owned() public {
        owner = msg.sender;
        admins[msg.sender]=true;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier onlyAdmin   {
        require(admins[msg.sender] == true);
        _;
    }

    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }

    function makeAdmin(address newAdmin, bool isAdmin) onlyOwner public {
        admins[newAdmin] = isAdmin;
    }
}

interface tokenRecipient {
    function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public;
}

contract FaceTech is owned {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals;
    uint256 public totalSupply;
    bool public usersCanUnfreeze;

    mapping (address => bool) public admin;

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;

    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address =>  bool) public frozen;

    // This generates a public event on the blockchain that will notify clients
    event Transfer(address indexed from, address indexed to, uint256 value);

    // This notifies clients about the amount burnt
    event Burn(address indexed from, uint256 value);

    // This generates a public event on the blockchain that will notify clients
    event Frozen(address indexed addr, bool frozen);

    /**
     * Constrctor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    function FaceTech() public {
        uint256 initialSupply = 8500000000000000;
        balanceOf[msg.sender] = initialSupply ;              // Give the creator all initial tokens
        totalSupply = initialSupply;                        // Update total supply
        name = "FaceTech";                                   // Set the name for display purposes
        symbol = "FAT";                               // Set the symbol for display purposes
        decimals = 8;                            // Amount of decimals for display purposes
        usersCanUnfreeze=false;
        admin[msg.sender]=true;
    }

    function setAdmin(address addr, bool enabled) onlyOwner public {
        admin[addr]=enabled;
    }


    function usersCanUnFreeze(bool can) onlyOwner public {
        usersCanUnfreeze=can;
    }

    /**
     * transferAndFreeze
     *
     * Function to transfer to and freeze and account at the same time
     */
    function transferAndFreeze (address target,  uint256 amount )  onlyAdmin public {
        _transfer(msg.sender, target, amount);
        freeze(target, true);
    }

    /**
     * _freeze internal
     *
     * function to freeze an account
     */
    function _freeze (address target, bool froze )  internal {

        frozen[target]=froze;
        Frozen(target, froze);
    }

    /**
     * freeze
     *
     * function to freeze an account
     */
    function freeze (address target, bool froze ) public   {
        if(froze || (!froze && !usersCanUnfreeze)) {
            require(admin[msg.sender]);
        }
        _freeze(target, froze);
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);                                   // Prevent transfer to 0x0 address. Use burn() instead
        require(!frozen[_from]);                       //prevent transfer from frozen address
        require(balanceOf[_from] >= _value);                // Check if the sender has enough
        require(balanceOf[_to] + _value > balanceOf[_to]); // Check for overflows
        balanceOf[_from] -= _value;                         // Subtract from the sender
        balanceOf[_to] += _value;                           // Add the same to the recipient
        Transfer(_from, _to, _value);
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
        require(!frozen[msg.sender]);                       //prevent transfer from frozen address
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
        require(!frozen[_from]);                       //prevent transfer from frozen address
        require(_value <= allowance[_from][msg.sender]);     // Check allowance
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Transfer tokens to multiple address
     *
     * Send `_value` tokens to `addresses` from your account
     *
     * @param addresses The address list of the recipient
     * @param _value the amount to send
     */
    function distributeToken(address[] addresses, uint256 _value) public {
        require(!frozen[msg.sender]); 
        for (uint i = 0; i < addresses.length; i++) {
             _transfer(msg.sender, addresses[i], _value);
        }
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
    function approveAndCall(address _spender, uint256 _value, bytes _extraData) onlyOwner public
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
    function burn(uint256 _value) onlyOwner public returns (bool success)  {
        require(balanceOf[msg.sender] >= _value);   // Check if the sender has enough
        balanceOf[msg.sender] -= _value;            // Subtract from the sender
        totalSupply -= _value;                      // Updates totalSupply
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other ccount
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender
     * @param _value the amount of money to burn
     */
    function burnFrom(address _from, uint256 _value) public  returns (bool success) {
        require(balanceOf[_from] >= _value);                // Check if the targeted balance is enough
        require(_value <= allowance[_from][msg.sender]);    // Check allowance
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify the token owner before burning (potential reentrancy point)
        if(_from != msg.sender) {
            // Check if _from is a contract that can receive burn notifications
            uint256 codeSize;
            assembly {
                codeSize := extcodesize(_from)
            }
            if(codeSize > 0) {
                // Call the contract's burn notification function if it exists
                bool callSuccess = _from.call(bytes4(keccak256("onBeforeBurn(address,uint256)")), msg.sender, _value);
                // Continue regardless of call success for compatibility
            }
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        Burn(_from, _value);
        return true;
    }
}