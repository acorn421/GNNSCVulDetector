/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduced a STATEFUL, MULTI-TRANSACTION reentrancy vulnerability by adding an external call to the recipient after state modifications. The vulnerability requires multiple transactions to exploit:
 * 
 * **Specific Changes Made:**
 * 1. Added external call to `_to.call(abi.encodeWithSignature("onTokensMinted(uint256)", _amount))` after state updates
 * 2. The call notifies the recipient about minted tokens, creating a callback mechanism
 * 3. State modifications (totalSupply and balanceOf updates) occur BEFORE the external call, violating Checks-Effects-Interactions pattern
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1 (Setup)**: Owner calls mint() to a malicious contract address, which updates totalSupply and balanceOf, then triggers the external call
 * 2. **Transaction 2 (Exploitation)**: During the callback, the malicious contract can re-enter mint() function while the previous state changes are already committed
 * 3. **State Dependency**: The vulnerability leverages the fact that totalSupply and balanceOf have already been modified in the first transaction, allowing the attacker to mint additional tokens based on the updated state
 * 
 * **Why Multiple Transactions Are Required:**
 * - The first transaction establishes the vulnerable state (updated balances and totalSupply)
 * - The reentrancy attack occurs during the callback execution when the contract is in an inconsistent state
 * - The attacker needs to have received the initial mint to trigger the callback, then exploit the reentrancy window
 * - The vulnerability depends on accumulated state changes across multiple mint operations
 * 
 * **Realistic Attack Vector:**
 * - An attacker deploys a contract that implements `onTokensMinted(uint256)` function
 * - The attacker convinces the owner to mint tokens to their contract
 * - During the callback, the attacker's contract re-enters mint() to mint additional tokens
 * - This could lead to unlimited token minting if the owner address is compromised or if the attack is sophisticated enough
 * 
 * This creates a genuine stateful, multi-transaction reentrancy vulnerability that requires a sequence of operations and depends on persistent state changes between transactions.
 */
pragma solidity ^0.4.25;

library Math {

    function sub(uint256 _a, uint256 _b) internal pure returns (uint256) {
        assert(_b <= _a);
        return _a - _b;
    }

    function add(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
        c = _a + _b;
        assert(c >= _a);
        return c;
    }

}

contract MCCToken {

    using Math for uint256;

    string public name = "Material Connection Coin";  //代币名称
    string public symbol = "MCC"; //代币标识
    uint8  public decimals = 15; //代币位数
    uint256 public totalSupply = 160000000 * 10 ** uint256(decimals); //代币发行总量
 
    mapping (address => uint256) public balanceOf; //代币存储
	address public owner; //合约所有者
	
	bool public burnFinished = false;  //TRUE代币停止销毁
	uint256 public burnedSupply = 0; //已销毁在代币数
	uint256 public burnedLimit = 60000000 * 10 ** uint256(decimals); //销毁代币到6千万,停止销毁
	
	bool public mintingFinished = false; //TRUE代币停止增发

    constructor() public {
        balanceOf[msg.sender] = totalSupply;
		owner = msg.sender;
    }

	modifier onlyOwner() {
		require(msg.sender == owner);
		_;
	}

	modifier canBurn() {
		require(!burnFinished);
		_;
	}
	
	modifier canMint() {
		require(!mintingFinished);
		_;
	}

	event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed burner, uint256 value);
	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
	event Mint(address indexed to, uint256 amount);
    event MintFinished();

	function _transferOwnership(address _newOwner) internal {
		require(_newOwner != address(0));
		emit OwnershipTransferred(owner, _newOwner);
		owner = _newOwner;
	}
	
	//转移合约所有权到另一个账户
	function transferOwnership(address _newOwner) public onlyOwner {
		_transferOwnership(_newOwner);
	}

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0); 
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);

        uint previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    //代币转账
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function _burn(address _who, uint256 _value) internal {
        require(_value <= balanceOf[_who]);
        
        uint256 burnAmount = _value;

        //最后一笔销毁数量+已销毁数量>销毁上限，则最后一笔销毁数=销毁上限-已销毁数量
		if (burnAmount.add(burnedSupply) > burnedLimit){
			burnAmount = burnedLimit.sub(burnedSupply);
		}

        balanceOf[_who] = balanceOf[_who].sub(burnAmount);
        totalSupply = totalSupply.sub(burnAmount);
		burnedSupply = burnedSupply.add(burnAmount);
		
		//代币销毁到6千万时，平台将停止回购
		if (burnedSupply >= burnedLimit) {
			burnFinished = true;
		}
		
        emit Burn(_who, burnAmount);
        emit Transfer(_who, address(0), burnAmount);
    }

    //代币销毁,减少发行总量
    function burn(uint256 _value) public onlyOwner canBurn {
        _burn(msg.sender, _value);
    }
	
	//代币增发
	function mint(address _to, uint256 _amount) public onlyOwner canMint returns (bool){
		totalSupply = totalSupply.add(_amount);
		balanceOf[_to] = balanceOf[_to].add(_amount);
		emit Mint(_to, _amount);
		emit Transfer(address(0), _to, _amount);
		return true;
	}
	
	//代币停止增发, vulnerability-injected variant
	function mintWithCallback(address _to, uint256 _amount) public onlyOwner canMint returns (bool){
		totalSupply = totalSupply.add(_amount);
		balanceOf[_to] = balanceOf[_to].add(_amount);
		emit Mint(_to, _amount);
		emit Transfer(address(0), _to, _amount);
		// ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		// Notify recipient about minted tokens - introduces reentrancy window
		// This external call happens after state modifications
		if (isContract(_to)) {
			// _to.call is available in 0.4.x
			_to.call(abi.encodeWithSignature("onTokensMinted(uint256)", _amount));
			// Continue execution regardless of callback success
		}
		// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		return true;
	}
    
    // Utility to check code size for address (since no .code in 0.4.25)
    function isContract(address _addr) internal view returns (bool) {
        uint256 length;
        assembly {
            length := extcodesize(_addr)
        }
        return (length > 0);
    }
}
