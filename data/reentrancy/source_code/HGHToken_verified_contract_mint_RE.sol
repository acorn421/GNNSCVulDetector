/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a minting registry before state updates. The vulnerability requires:
 * 
 * 1. **State Setup (Transaction 1)**: Owner deploys a malicious contract that implements IMintingRegistry and sets it as mintingRegistry
 * 2. **Multi-Transaction Exploitation**: The malicious registry contract re-enters mint() during notifyMint(), allowing cumulative token inflation across multiple nested calls
 * 3. **Persistent State Impact**: Each reentrancy call permanently increases totalSupply and owner balance, creating exponential token inflation
 * 
 * **Exploitation Sequence:**
 * - Transaction 1: Owner sets malicious registry contract
 * - Transaction 2: Owner calls mint(1000) → triggers notifyMint() → malicious contract re-enters mint(1000) → creates cascade of nested calls
 * - Each nested call adds to totalSupply and balance, violating the intended single-mint behavior
 * 
 * **Multi-Transaction Nature:**
 * The vulnerability cannot be exploited in a single transaction because:
 * - Requires prior setup of the malicious registry contract
 * - Depends on accumulated state changes from nested reentrancy calls
 * - Each re-entrant call builds upon previous state modifications
 * - The impact grows exponentially with each nested call in the sequence
 * 
 * This creates a realistic reentrancy vulnerability that follows the Checks-Effects-Interactions violation pattern commonly seen in production code.
 */
pragma solidity ^0.4.16;

contract owned {
    address public owner;
    function owned() public {
        owner = msg.sender;
    }
    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }
    function transferOwnership(address newOwner) onlyOwner public {
        owner = newOwner;
    }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/// ERC20 standard，Define the minimum unit of money to 18 decimal places,
/// transfer out, destroy coins, others use your account spending pocket money.
contract TokenERC20 {
    uint256 public totalSupply;
    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    /**
     * Internal transfer, only can be called by this contract.
     */
    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account.
     *
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    /**
     * Transfer tokens from other address.
     *
     * Send `_value` tokens to `_to` in behalf of `_from`.
     *
     * @param _from The address of the sender.
     * @param _to The address of the recipient.
     * @param _value the amount to send.
     */
    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    /**
     * Set allowance for other address.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     */
    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        require((_value == 0) || (allowance[msg.sender][_spender] == 0));
        allowance[msg.sender][_spender] = _value;
        return true;
    }

    /**
     * Set allowance for other address and notify.
     *
     * Allows `_spender` to spend no more than `_value` tokens in your behalf, and then ping the contract about it.
     *
     * @param _spender The address authorized to spend.
     * @param _value the max amount they can spend.
     * @param _extraData some extra information to send to the approved contract.
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
     * Remove `_value` tokens from the system irreversibly.
     *
     * @param _value the amount of money to burn.
     */
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;
        Burn(msg.sender, _value);
        return true;
    }

    /**
     * Destroy tokens from other account.
     *
     * Remove `_value` tokens from the system irreversibly on behalf of `_from`.
     *
     * @param _from the address of the sender.
     * @param _value the amount of money to burn.
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

/****************************/
/*       ------------        */
/*       HGH TOKEN        */
/*       ------------        */
/****************************/

// Forward declaration for IMintingRegistry used in HGHToken
interface IMintingRegistry {
    function notifyMint(address minter, uint amount) external;
}

/// HGH Protocol Token.
contract HGHToken is owned, TokenERC20 {

    string public constant name = "Human Growth Hormone";
    string public constant symbol = "HGH";
    uint8 public constant decimals = 0;
    uint256 public totalSupply = 1000000;
    address public mintingRegistry;

    /* Initializes contract with initial supply tokens to the creator of the contract. */
    function HGHToken() public {
        balanceOf[msg.sender] = totalSupply;
    }

    function mint(uint amount) onlyOwner public {
        require(amount != 0x0);
        require(amount < 1e60);
        require(totalSupply + amount > totalSupply);
   
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // Notify minting registry before state updates (vulnerable pattern)
        if (mintingRegistry != address(0)) {
            IMintingRegistry(mintingRegistry).notifyMint(msg.sender, amount);
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
    }
}
