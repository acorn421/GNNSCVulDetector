/*
 * ===== SmartInject Injection Details =====
 * Function      : addNewAccount
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 6 findings
 * Total Found   : 6 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 * 3. reentrancy-no-eth (SWC-107)
 * ... and 3 more
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Preserved External Call Timing**: Kept the external call to `creditbitContract.mintMigrationTokens()` before state updates, creating the classic reentrancy attack vector.
 * 
 * 2. **Added Vulnerable State Management**: Introduced temporary state variables (`tempCreditsExchanged`, `tempMigrationCounter`, `currentDeposited`) that create a false sense of security while the actual vulnerability remains.
 * 
 * 3. **Critical State Update Ordering**: The most critical vulnerability is that `AccountLocation[_etherAddress] = location` happens AFTER the external call. This means:
 *    - Transaction 1: Attacker calls addNewAccount, during mintMigrationTokens, the malicious contract reenters
 *    - During reentrancy: AccountLocation[_etherAddress] is still 0, so the reentrant call goes through the "new account" path
 *    - Transaction 1 completes: AccountLocation gets set, but damage is already done
 *    - Transaction 2+: Attacker can exploit the inconsistent state created by the reentrancy
 * 
 * 4. **Multi-Transaction Exploitation Path**:
 *    - **Setup Phase (Transaction 1)**: Attacker deploys malicious contract implementing mintMigrationTokens
 *    - **Exploitation Phase (Transaction 2)**: Attacker calls addNewAccount, triggering reentrancy during mintMigrationTokens
 *    - **Reentrant Call**: Malicious contract calls addNewAccount again before AccountLocation is updated
 *    - **State Corruption**: Both calls increment migrationAccountCounter and add to creditsExchanged, but only one AccountLocation entry is created
 *    - **Follow-up Exploitation (Transaction 3+)**: Attacker can now exploit the inconsistent state where multiple migration accounts exist for the same address
 * 
 * 5. **Realistic Implementation**: The vulnerability appears as a legitimate attempt to add state validation and rollback mechanisms, making it subtle and realistic for production code.
 * 
 * This vulnerability requires multiple transactions because:
 * - The first transaction sets up the attack by calling the malicious contract
 * - The reentrancy occurs during the external call, requiring the attacker's contract to be already deployed and callable
 * - The state corruption persists between transactions, enabling follow-up exploitation
 * - The full impact only becomes apparent when subsequent transactions interact with the corrupted state
 */
pragma solidity ^0.4.8;

pragma solidity ^0.4.8;

contract ICreditBIT{
    function mintMigrationTokens(address _reciever, uint _amount) returns (uint error) {}
}

contract CreditMC {

	struct MigrationAccount{
		string legacyCreditAddresses;
		address newCreditAddress;
        uint creditbitsDeposited;
		uint newTotalSupplyVote;
		uint coreDevteamRewardVote;
	}

	address public dev;
	address public curator;
	bool public migrationEnded;
	bool public devRewardClaimed;
	bool public daoStakeClaimed;

	ICreditBIT creditbitContract;

	uint public creditsExchanged;
	uint public realVotedSupply;
	uint public realSupplyWeight;
	uint public realDevReward;
	uint public realDevRewardWeight;
	
	function getCurrentSupplyVote() constant returns(uint supplyVote){
	    return realVotedSupply / 10**8;
	}
	function getCurrentDevReward() constant returns(uint rewardVote){
	    return ((((realVotedSupply - creditsExchanged) * (realDevReward))) / 10000) / 10**8;
	}
    function getCurrentDaoStakeSupply() constant returns(uint rewardVote){
	    return ((((realVotedSupply - creditsExchanged) * (10000 - realDevReward))) / 10000) / 10**8;
	}
	function getCurrentCreditsExchanged() constant returns(uint crbExchanged){
	    return creditsExchanged / 10**8;
	}
	
	function getMigrationAccount(address _accountAddress) constant returns (bytes, address, uint, uint, uint){
	    MigrationAccount memory tempMigrationAccount = MigrationAccounts[AccountLocation[_accountAddress]];
        return (bytes(tempMigrationAccount.legacyCreditAddresses), 
            tempMigrationAccount.newCreditAddress, 
            tempMigrationAccount.creditbitsDeposited,
            tempMigrationAccount.newTotalSupplyVote,
            tempMigrationAccount.coreDevteamRewardVote
        );
	}

	uint public migrationAccountCounter;
	mapping (uint => MigrationAccount) MigrationAccounts;
	mapping (address => uint) AccountLocation;

	function CreditMC(){
		dev = msg.sender;
		migrationAccountCounter = 1;
		migrationEnded = false;
		devRewardClaimed = false;
	}

	function addNewAccount(string _legacyCreditAddress, address _etherAddress, uint _numberOfCoins, uint _totalSupplyVote, uint _coreDevTeamReward) returns (uint error){
        if (migrationEnded) {return 1;}
		if (msg.sender != curator){ return 1; }

        uint location;
        uint message;
        
		if (AccountLocation[_etherAddress] == 0){
		    migrationAccountCounter += 1;
		    location = migrationAccountCounter;
		    
		    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		    // Store temporary state for potential reentrancy validation
		    uint tempCreditsExchanged = creditsExchanged;
		    uint tempMigrationCounter = migrationAccountCounter;
		    
		    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		    message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
		    if (message == 0 && address(creditbitContract) != 0x0){
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		        // Vulnerable: State updates happen after external call without reentrancy protection
		        // The external call could reenter and modify state before these updates complete
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		        MigrationAccounts[location].legacyCreditAddresses = _legacyCreditAddress;
		        MigrationAccounts[location].newCreditAddress = _etherAddress;
                MigrationAccounts[location].creditbitsDeposited = _numberOfCoins;
		        MigrationAccounts[location].newTotalSupplyVote = _totalSupplyVote;
		        MigrationAccounts[location].coreDevteamRewardVote = _coreDevTeamReward;
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		        
		        // Vulnerable: AccountLocation update happens after external call
		        // This creates a window where the same address could be processed multiple times
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		        AccountLocation[_etherAddress] = location;
		        
		        creditsExchanged += _numberOfCoins;
		        calculateVote(_totalSupplyVote, _coreDevTeamReward, _numberOfCoins);
		    }else{
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		        // Rollback counter if minting failed, but this doesn't protect against reentrancy
		        migrationAccountCounter = tempMigrationCounter - 1;
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		        return 1;
		    }
		}else{
		    location = AccountLocation[_etherAddress];
		    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		    
		    // Store current state for validation
		    uint currentDeposited = MigrationAccounts[location].creditbitsDeposited;
		    
		    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		    message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
		    if (message == 0 && address(creditbitContract) != 0x0){
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
		        // Vulnerable: State update after external call without reentrancy check
		        // Reentrant calls could manipulate creditbitsDeposited before this update
		        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
		        MigrationAccounts[location].creditbitsDeposited += _numberOfCoins;
		        
		        creditsExchanged += _numberOfCoins;
		        calculateVote(_totalSupplyVote, _coreDevTeamReward, _numberOfCoins);
		    }else{
		        return 1;
		    }
		}
		return 0;
	}
	//todo: check on testnet
    function calculateVote(uint _newSupplyVote, uint _newRewardVote, uint _numOfVotes) internal{
        uint newSupply = (realVotedSupply * realSupplyWeight + _newSupplyVote * _numOfVotes) / (realSupplyWeight + _numOfVotes);
        uint newDevReward = (1000000*realDevReward * realDevRewardWeight + 1000000 * _newRewardVote * _numOfVotes) / (realDevRewardWeight + _numOfVotes);
    
        realVotedSupply = newSupply;
        realSupplyWeight = realSupplyWeight + _numOfVotes;
        realDevReward = newDevReward/1000000;
        realDevRewardWeight = realDevRewardWeight + _numOfVotes;
    }

	function setCreditMCCurator(address _curatorAddress) returns (uint error){
		if (msg.sender != dev){ return 1; }

		curator = _curatorAddress;
		return 0;
	}
	
	function setCreditbit(address _bitAddress) returns (uint error){
        if (msg.sender != dev) {return 1;}
        
        creditbitContract = ICreditBIT(_bitAddress);
        return 0;
    }
    function getCreditbitAddress() constant returns (address bitAddress){
        return address(creditbitContract);
    }
    
    function endMigration() returns (uint error){
        if (msg.sender != dev){ return 1; }
        
        migrationEnded = true;
        return 0;
    }
    
	
    function claimDevReward(address _recipient) returns (uint error){
        if (msg.sender != dev){ return 1; }
        if (devRewardClaimed){ return 1; }
        if (!migrationEnded){ return 1;}
        
        uint message = creditbitContract.mintMigrationTokens(
            _recipient, 
            (((realVotedSupply - creditsExchanged) * (realDevReward)) / 10000)
        );
        if (message != 0) { return 1; }
        
        creditsExchanged += (((realVotedSupply - creditsExchanged) * (realDevReward)) / 10000);
        devRewardClaimed = true;
        return 0;
    }
    
    function claimDaoStakeSupply(address _recipient) returns (uint error){
        if (msg.sender != dev){ return 1; }
        if (!devRewardClaimed){ return 1; }
        if (!migrationEnded){ return 1; }
        if (daoStakeClaimed){ return 1; }
        
        uint message = creditbitContract.mintMigrationTokens(
            _recipient, 
            realVotedSupply - creditsExchanged
        );
        if (message != 0) { return 1; }
        
        creditsExchanged += (realVotedSupply - creditsExchanged);
        daoStakeClaimed = true;
        return 0;
    }
    

	function () {
		throw;
	}
}