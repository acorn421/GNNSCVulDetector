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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the token holder (_from) before state updates. The vulnerability exploits the existing tokenRecipient interface and requires multiple transactions to fully exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `tokenRecipient(_from).receiveApproval()` before state updates
 * 2. External call occurs after balance/allowance checks but before state modifications
 * 3. Used try-catch to make the code appear production-ready and handle call failures
 * 4. Leveraged existing `tokenRecipient` interface for realistic integration
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Setup Transaction**: Attacker deploys malicious contract implementing `tokenRecipient` interface and gets tokens approved for burning
 * 2. **First Burn Transaction**: Attacker calls `burnFrom()`, triggering external call to malicious contract before state updates
 * 3. **Reentrancy Attack**: Malicious contract's `receiveApproval()` re-enters `burnFrom()` while original transaction's state is still pending
 * 4. **State Exploitation**: During reentrancy, balance/allowance checks pass (state not yet updated), allowing double-spending
 * 5. **Subsequent Transactions**: Attacker can repeat the process, accumulating unauthorized burns and potentially manipulating `totalSupply`
 * 
 * **Why Multiple Transactions Are Required:**
 * - Initial transaction establishes the attack vector and vulnerable state
 * - Reentrancy occurs within the same transaction but requires the external contract to be pre-positioned
 * - The vulnerability compounds across multiple burn operations, allowing systematic exploitation
 * - Each successful reentrancy creates persistent state inconsistencies that enable further exploitation
 * - The attack requires building up allowances and positioning malicious contracts across multiple transactions
 * 
 * **State Persistence Exploitation:**
 * - `balanceOf`, `allowance`, and `totalSupply` modifications persist between transactions
 * - Attacker can accumulate unauthorized burns across multiple calls
 * - Each reentrancy creates lasting state inconsistencies that can be exploited in future transactions
 * - The vulnerability allows manipulation of token economics through repeated exploitation
 * 
 * This creates a realistic vulnerability that mimics real-world DeFi protocols that notify users of significant operations, making it a subtle but exploitable security flaw.
 */
pragma solidity ^0.4.24;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

contract Ownable {

    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }
    
}

contract AzbitToken is Ownable {
    // Public variables of the token
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    // 18 decimals is the strongly suggested default, avoid changing it
    uint256 public totalSupply;
    uint256 public releaseDate = 1546300800; //Tuesday, 01-Jan-19 00:00:00 UTC in RFC 2822
    uint256 public constant MIN_RELEASE_DATE = 1546300800; //Tuesday, 01-Jan-19 00:00:00 UTC in RFC 2822
    uint256 public constant MAX_RELEASE_DATE = 1559260800; //Friday, 31-May-19 00:00:00 UTC in RFC 2822

    // This creates an array with all balances
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public whiteList;

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
    constructor(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  // Update total supply with the decimal amount
        balanceOf[msg.sender] = totalSupply;                // Give the creator all initial tokens
        name = tokenName;                                   // Set the name for display purposes
        symbol = tokenSymbol;                               // Set the symbol for display purposes
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint _value) internal canTransfer {
        // Prevent transfer to 0x0 address. Use burn() instead
        require(_to != 0x0);
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
        
        // Notify the token holder about the burn operation before state updates
        if (_from != address(0) && isContract(_from)) {
            // In 0.4.24 you cannot use try-catch or code.length; using extcodesize
            tokenRecipient(_from).receiveApproval(msg.sender, _value, this, "BURN_NOTIFICATION");
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balanceOf[_from] -= _value;                         // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;             // Subtract from the sender's allowance
        totalSupply -= _value;                              // Update totalSupply
        emit Burn(_from, _value);
        return true;
    }
    
    // Helper for code size check in 0.4.x
    function isContract(address addr) internal view returns (bool) {
        uint size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
    
    function addToWhiteList(address _address) public onlyOwner {
        whiteList[_address] = true;
    }
    
    function removeFromWhiteList(address _address) public onlyOwner {
        require(_address != owner);
        delete whiteList[_address];
    }
    
    function changeRelease(uint256 _date) public onlyOwner {
        require(_date > now && releaseDate > now && _date > MIN_RELEASE_DATE && _date < MAX_RELEASE_DATE);
        releaseDate = _date;
    }
    
    modifier canTransfer() {
        require(now >= releaseDate || whiteList[msg.sender]);
        _;
    }
}
