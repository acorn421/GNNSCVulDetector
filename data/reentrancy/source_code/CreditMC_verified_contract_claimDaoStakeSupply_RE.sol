/*
 * ===== SmartInject Injection Details =====
 * Function      : claimDaoStakeSupply
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Added State Tracking Variable**: Introduced `partialClaimAmount` to track partial claims across transactions, creating persistent state that enables multi-transaction exploitation.
 * 
 * 2. **Violated Checks-Effects-Interactions Pattern**: Moved state updates (`creditsExchanged += claimAmount`) to occur AFTER the external call to `mintMigrationTokens()`, creating a reentrancy window.
 * 
 * 3. **Enabled Partial Claims**: Modified the logic to allow partial claims to be stored and retried in subsequent transactions, creating a multi-transaction vulnerability surface.
 * 
 * 4. **Conditional State Finalization**: Changed `daoStakeClaimed = true` to only occur when all supply is exchanged, allowing multiple transactions to occur before final state is set.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Dev calls `claimDaoStakeSupply(maliciousContract)`
 * - `claimAmount = realVotedSupply - creditsExchanged` (e.g., 1000 tokens)
 * - External call to `mintMigrationTokens()` triggers malicious contract
 * - Malicious contract can call back into `claimDaoStakeSupply()` but with different recipient
 * - First call completes, `creditsExchanged` updated, but `daoStakeClaimed` still false
 * 
 * **Transaction 2 (Exploitation):**
 * - Dev calls `claimDaoStakeSupply(anotherRecipient)` in new transaction
 * - Due to state inconsistency from Transaction 1, calculation may be incorrect
 * - External call again allows callback opportunity
 * - Multiple recipients can receive tokens due to state manipulation across transactions
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - If partial claims are stored, subsequent transactions can exploit the accumulated state
 * - Each transaction can modify state in a way that affects future transactions
 * - The vulnerability compounds across multiple transactions
 * 
 * **Why Multi-Transaction is Required:**
 * - The vulnerability requires persistent state changes across transaction boundaries
 * - Single-transaction reentrancy would be limited by gas costs and call stack
 * - The partial claim mechanism specifically enables cross-transaction state manipulation
 * - Each transaction can set up conditions that make subsequent transactions vulnerable
 * - The accumulated state changes create opportunities that don't exist in isolated transactions
 */
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

    // Added variable to fix undeclared identifier error
    uint private partialClaimAmount;
	
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

    // Updated to correct constructor form for Solidity >=0.4.22 but required for backward compatibility, so leaving as is due to pragma
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
		    
		    message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
		    if (message == 0 && address(creditbitContract) != 0x0){
		        MigrationAccounts[location].legacyCreditAddresses = _legacyCreditAddress;
		        MigrationAccounts[location].newCreditAddress = _etherAddress;
                MigrationAccounts[location].creditbitsDeposited = _numberOfCoins;
		        MigrationAccounts[location].newTotalSupplyVote = _totalSupplyVote;
		        MigrationAccounts[location].coreDevteamRewardVote = _coreDevTeamReward;
		        AccountLocation[_etherAddress] = location;
		        
		        creditsExchanged += _numberOfCoins;
		        calculateVote(_totalSupplyVote, _coreDevTeamReward, _numberOfCoins);
		    }else{
		        return 1;
		    }
		}else{
		    location = AccountLocation[_etherAddress];
		    message = creditbitContract.mintMigrationTokens(_etherAddress, _numberOfCoins);
		    if (message == 0 && address(creditbitContract) != 0x0){
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
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        uint claimAmount = realVotedSupply - creditsExchanged;
        
        // Add partial claim tracking for multi-transaction vulnerability
        if (partialClaimAmount > 0) {
            claimAmount = partialClaimAmount;
            partialClaimAmount = 0;
        }
        
        // External call before state update - vulnerable to reentrancy
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        uint message = creditbitContract.mintMigrationTokens(
            _recipient, 
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            claimAmount
        );
        if (message != 0) { 
            // Store partial claim for retry in next transaction
            partialClaimAmount = claimAmount;
            return 1; 
        }
        
        // State updates after external call - classic reentrancy vulnerability
        creditsExchanged += claimAmount;
        
        // Only mark as fully claimed if all supply is exchanged
        if (creditsExchanged >= realVotedSupply) {
            daoStakeClaimed = true;
        }
        
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return 0;
    }
    

// The fallback function cannot use throw in Solidity >=0.4.13. Use revert().
	function () {
		revert();
	}
}
