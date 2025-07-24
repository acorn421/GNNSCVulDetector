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
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external callback to the token holder before updating the allowance. This creates a classic check-effects-interaction pattern violation where:
 * 
 * 1. **Specific Code Changes:**
 *    - Added external call `IBurnCallback(_from).onTokenBurn(msg.sender, _value)` to notify the token holder
 *    - Moved the allowance update `allowance[_from][msg.sender] -= _value` to occur AFTER the external call
 *    - Wrapped the callback in a try-catch to maintain functionality when _from is not a contract
 *    - Added check `_from.code.length > 0` to only call contracts
 * 
 * 2. **Multi-Transaction Exploitation Path:**
 *    - **Transaction 1**: Attacker deploys malicious contract and gets approval from victim to burn tokens
 *    - **Transaction 2**: Attacker calls burnFrom() which triggers the callback to victim's contract
 *    - **During Callback**: Victim's contract can re-enter burnFrom() because allowance hasn't been decremented yet
 *    - **Result**: More tokens are burned than the original allowance permitted, with state accumulating across multiple reentrancy calls
 * 
 * 3. **Why Multi-Transaction is Required:**
 *    - The vulnerability requires the ERC20 allowance mechanism (approve + burnFrom pattern)
 *    - Initial approval transaction must happen before the vulnerable burnFrom call
 *    - The exploit accumulates state across multiple reentrancy calls within the callback
 *    - Each reentrant call burns additional tokens beyond the intended allowance
 *    - The persistent allowance state enables the vulnerability across transaction boundaries
 * 
 * This creates a realistic vulnerability where token burn notifications inadvertently enable reentrancy attacks on the allowance system.
 */
pragma solidity ^0.4.18;

contract Ownable {
  address public owner;

  event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

  function Ownable() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner);
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    OwnershipTransferred(owner, newOwner);
    owner = newOwner;
  }
}

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) public; }

// Added interface as required for burnFrom vulnerable callback
interface IBurnCallback {
    function onTokenBurn(address burner, uint256 value) external;
}

contract BING is Ownable {
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);

    function BING(
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol) 
        public {
        totalSupply = initialSupply * 10 ** uint256(decimals); 
        balanceOf[msg.sender] = totalSupply;           
        name = tokenName;                           
        symbol = tokenSymbol; }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0);
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value > balanceOf[_to]);
        uint previousBalances = balanceOf[_from] + balanceOf[_to];
        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        Transfer(_from, _to, _value);
        assert(balanceOf[_from] + balanceOf[_to] == previousBalances); }

    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value); }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);  
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true; }

    function approve(address _spender, uint256 _value) public
        returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true; }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool success) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, this, _extraData);
            return true; } }

    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;            
        totalSupply -= _value;                  
        Burn(msg.sender, _value);
        return true; }

    function burnFrom(address _from, uint256 _value) public returns (bool success) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);  
        balanceOf[_from] -= _value;                         
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        totalSupply -= _value;
        
        // Vulnerable external call before allowance update
        if (isContract(_from)) {
            IBurnCallback(_from).onTokenBurn(msg.sender, _value);
        }
        
        allowance[_from][msg.sender] -= _value;  // Moved after external call        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        Burn(_from, _value);
        return true; }
    
    // Helper function to determine if address is a contract (Solidity <0.5 compatible)
    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }
}