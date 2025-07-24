/*
 * ===== SmartInject Injection Details =====
 * Function      : burn
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback mechanism before state updates. The vulnerability allows malicious contracts to re-enter the burn function during the burnCallback execution, enabling them to burn more tokens than they actually own across multiple transactions.
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call Before State Updates**: Introduced a callback to `msg.sender` if it's a contract, violating the Checks-Effects-Interactions (CEI) pattern
 * 2. **Preserved Original Functionality**: The burn function still performs its intended token burning operations
 * 3. **Made Callback Optional**: Used try-catch to ensure the function works even if callback fails
 * 4. **Realistic Integration**: The burnCallback pattern is common in modern DeFi protocols for notifications
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker contract calls `burn(100)` with 100 token balance
 *    - Function checks balance (100 >= 100) ✓
 *    - External call to `burnCallback(100)` on attacker contract
 *    - Attacker's fallback re-enters `burn(100)` before state changes
 *    - Second call checks same balance (still 100 >= 100) ✓
 *    - Both calls complete, burning 200 tokens total but only had 100
 * 
 * 2. **Transaction 2**: Attacker repeats pattern with any remaining balance
 *    - Continues exploitation across multiple transactions
 *    - Each transaction amplifies the burn amount through reentrancy
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires the attacker to set up a malicious contract with burnCallback
 * - State accumulation: Each transaction builds on the previous exploit
 * - The attacker needs multiple calls to maximize token burning beyond their actual balance
 * - Gas limits prevent infinite reentrancy in a single transaction, making multi-transaction exploitation necessary
 * 
 * **State Persistence Factor:**
 * - `balanceOf` and `totalSupply` changes persist between transactions
 * - Attacker can systematically exploit the vulnerability across multiple blocks
 * - Creates long-term state inconsistencies that compound over time
 */
pragma solidity ^0.4.16;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

// Added callback interface declaration for burn external call
interface IERC20Callback {
    function burnCallback(uint256 _value) external;
}

contract AZEEMCOIN {
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    uint256 public sellPrice = 1;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Burn(address indexed from, uint256 value);

    // Place the extcodesize helper function INSIDE the contract
    function extcodesize(address _addr) internal view returns (uint size) {
        assembly { size := extcodesize(_addr) }
    }

    function AZEEMCOIN(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals); 
        balanceOf[msg.sender] = totalSupply;         
        name = tokenName;                             
        symbol = tokenSymbol;                               
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal {
      
        require(_to != 0x0);
       
        require(balanceOf[_from] >= _value);
        
        require(balanceOf[_to] + _value >= balanceOf[_to]);
       
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
       
        balanceOf[_from] -= _value;
       
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        
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
     * Send `_value` tokens to `_to` on behalf of `_from`
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf
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
     * Allows `_spender` to spend no more than `_value` tokens on your behalf, and then ping the contract about it
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
        require(balanceOf[msg.sender] >= _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // VULNERABILITY: External call before state updates
        // Check if caller is a contract and has a burnCallback function
        if (extcodesize(msg.sender) > 0) {
            // Inline assembly to check code size since .code.length is not available in 0.4.16
            // Attempt to call burnCallback on the caller contract
            // This allows reentrancy before state changes
            address(msg.sender).call(bytes4(keccak256("burnCallback(uint256)")), _value);
        }
        // State changes happen AFTER external call - classic CEI violation
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
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
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] -= _value;     
        allowance[_from][msg.sender] -= _value;
        totalSupply -= _value;
        Burn(_from, _value);
        return true;
    }
}
