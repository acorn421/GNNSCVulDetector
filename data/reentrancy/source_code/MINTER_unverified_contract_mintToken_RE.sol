/*
 * ===== SmartInject Injection Details =====
 * Function      : mintToken
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
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to the target address before state updates. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call `target.call(abi.encodeWithSignature("onTokenMinted(uint256)", mintedAmount))` before state updates
 * 2. Added check `target.code.length > 0` to only call contracts (realistic safety measure)
 * 3. Used low-level call that continues execution regardless of callback success
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 1. **Transaction 1**: Attacker calls mintToken with a malicious contract address
 * 2. **During reentrancy**: The malicious contract's `onTokenMinted` callback is triggered BEFORE `balanceOf` and `totalSupply` are updated
 * 3. **In callback**: Attacker can call other functions (transfer, approve, or even mintToken again) while state is inconsistent
 * 4. **Transaction 2+**: Exploit the accumulated inconsistent state from previous transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability exploits the time window between the external call and state updates
 * - Attacker needs to accumulate state inconsistencies across multiple minting operations
 * - The `MaxSupply > totalSupply` check can be bypassed through accumulated state manipulation
 * - Each transaction builds upon the inconsistent state created in previous transactions
 * 
 * **Realistic Exploitation Scenario:**
 * - Attacker deploys malicious contract with `onTokenMinted` function
 * - During callback, attacker transfers tokens before balance is officially updated
 * - Attacker can potentially mint more tokens than MaxSupply allows by exploiting the timing gap
 * - Multiple transactions allow accumulation of these timing-based exploits
 */
pragma solidity ^0.4.25;

contract MINTER {
    string public name = "AD Revenue MINTER";      //  token name
    string public symbol = "MINTER";           //  token symbol
    string public version = "2.0";
    uint256 public decimals = 8;            //  token digit

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    uint256 public totalSupply = 1000000000000000000;
    uint256 public MaxSupply = 0;
    bool public stopped = true;

    //000 000 000 000 000 000
    address owner = 0x48850F503412d8A6e3d63541F0e225f04b13a544;
    address minter = 0x47c803871c99EC7180E50dcDA989320871FcBfEE;

    modifier isOwner {
        assert(owner == msg.sender);
        _;
    }

    modifier isMinter {
        assert(minter == msg.sender);
        _;
    }

    modifier validAddress {
        assert(0x0 != msg.sender);
        _;
    }

    constructor () public {
        MaxSupply = 10000000000000000000;
        balanceOf[owner] = totalSupply;
        emit Transfer(0x0, owner, totalSupply);
    }

    function changeOwner(address _newaddress) isOwner public {
        owner = _newaddress;
    }

    function changeMinter(address _new_mint_address) isOwner public {
        minter = _new_mint_address;
    }

    function airdropMinting(address[] _to_list, uint[] _values) isMinter public {
        require(_to_list.length == _values.length);
        for (uint i = 0; i < _to_list.length; i++) {
            mintToken(_to_list[i], _values[i]);
        }
    }

    function setMaxSupply(uint256 maxsupply_amount) isOwner public {
      MaxSupply = maxsupply_amount;
    }

    function mintToken(address target, uint256 mintedAmount) isMinter public {
      require(MaxSupply > totalSupply);
      // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
      
      // Add external call before state updates - vulnerability injection
      if (isContract(target)) {
          (bool success, ) = target.call(abi.encodeWithSignature("onTokenMinted(uint256)", mintedAmount));
          // Continue execution regardless of callback success
      }
      
      // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
      balanceOf[target] += mintedAmount;
      totalSupply += mintedAmount;
      emit Transfer(0, this, mintedAmount);
      emit Transfer(this, target, mintedAmount);
    }

    // Helper function to check if address is a contract (for Solidity ^0.4.x)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly { length := extcodesize(_addr) }
        return length > 0;
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address src, address dst, uint256 wad) public returns (bool success) {
        require(balanceOf[src] >= wad);
        require(allowance[src][msg.sender] >= wad);
        allowance[src][msg.sender] -= wad;
        balanceOf[src] -= wad;
        balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        require(_value == 0 || allowance[msg.sender][_spender] == 0);
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
